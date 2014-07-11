#!/usr/local/cpanel/3rdparty/bin/perl
# cpanel - cpapi.pl             Copyright(c) 2014 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited
use strict;
use warnings;

use Data::Dumper         ();
use Data::Dumper         ();
use Encode               ();
use Getopt::Long         ();
use HTTP::Cookies        ();
use IO::Prompt           ();
use JSON                 ();
use LWP::Protocol::https ();
use LWP::UserAgent       ();
use MIME::Base64         ();
use URI::Escape          ();
use utf8;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

# Presented output should be presentable.

# TODO: Most or all of these globals should go away.
my $username;
my $hostname = 'localhost';
my $protocol = 'https';
my $password;
my $accesshash_name = '/root/.accesshash';
my $debug;

my @call_params;

my $api_class;
my $module;
my $function;

# This is a global that gets modified in unsavory ways. I'm really, really sorry,
# like David Tennant telling you that you've got two shadows sorry.
my $security_token;

my $uapi_regex       = qr{\Auapi\z}sxmi;
my $whm_api_regex    = qr{\Awhm[01]\z}sxmi;
my $cpanel_api_regex = qr{\A^api[12]\z}sxmi;

Getopt::Long::GetOptions(
    'accesshash|a=s' => \$accesshash_name,
    'debug|d'        => \$debug,
    'help|h'         => \&help,
    'hostname|H=s'   => \$hostname,
    'insecure'       => sub { $protocol = 'http' },
    'username|u=s'   => \$username,
    'password|p'     => sub {
        local @ARGV = ();
        $password = prompt( 'Password: ', -e => '*' );
        return 1;
    },
    '<>' => \&process_non_option,
);

my $useragent;

# At this point, we know which API we're talking to.
# We have a username and password argument.
# We can set up authentication as necessary.

if ( $api_class =~ $whm_api_regex ) {
    $useragent = auth_for_whm( $username, $password, $accesshash_name );
}
elsif ( $api_class =~ $cpanel_api_regex || $api_class =~ $uapi_regex ) {
    $useragent = auth_for_cp( $username, $password, $accesshash_name );
}
else { print "Couldn't make head or tails of the API class.\n\n"; help(); }

my $url = assemble_url(
    'protocol'       => $protocol,
    'hostname'       => $hostname,
    'api_class'      => $api_class,
    'security_token' => $security_token,
    'module'         => $module,
    'function'       => $function,
    'username'       => $username,
    'params_ref'     => \@call_params,
);

if ($debug) { print "    request URL turned out to be $url\n"; }

my $response     = $useragent->post($url);
my $content      = Encode::encode_utf8( $response->decoded_content );
my $json_printer = JSON->new->pretty;

# Deliver report, plus Perlesque exception handling.
{
    local $@ = undef;
    $content = eval { JSON::decode_json($content) };
    if ($@) {

        # $content probably contains HTML due to a cPanel-provided error.
        # TODO: Break this out by HTTP status codes. That'll be cool.
        if ( $response->{'status'} == 301 ) {
            print "cPanel attempted to redirect to:\n";
            print Data::Dumper::Dumper($response);
            print "\nIs 'always redirect to SSL' turned on in Tweak Settings?\n";
        }
        else {
            print "decode_json died. Here's what it was passed:\n$content\n";
        }
        exit;
    }
    else {
        # Success!
        print $json_printer->encode($content);
    }
}

##################################################################################################################
#### Turning our inputs into what we can use
##################################################################################################################

# Expects something that Getopt::Long doesn't know how to handle.
# Returns 1.
sub process_non_option {
    my ( $opt_name, $opt_value ) = @_;
    if ($debug) { print "entered process_non_option\n"; }
    if ( $opt_name =~ /::/sxm ) {
        ( $api_class, $module, $function ) = process_call_name($opt_name);
    }
    else {
        push @call_params, process_parameter($opt_name);
    }
    return 1;
}

# Expects the part of @ARGV that represents which API call we are making.
# Something with names separated by ::
# Returns API class, module, and function name.
sub process_call_name {
    my ($call) = @_;
    if ($debug) { print "entered process_call_option\n"; }
    my @call_parts = split '::', $call;
    my ( $api_class, $module, $function );
    if ( $call_parts[0] =~ $uapi_regex ) {
        $api_class = shift @call_parts;
        $function  = pop @call_parts;
        $module    = join( '/', @call_parts, q{} );
    }
    elsif ( $call_parts[0] =~ $whm_api_regex || $call_parts[0] =~ $cpanel_api_regex ) {
        ( $api_class, $module, $function ) = @call_parts;
    }
    else { die 'API version is not clear. Use UAPI, API1, API2, WHM0, or WHM1.'; }
    return ( $api_class, $module, $function );
}

# Expects one parameter passed to the program. Where appropriate, prompts
# for the value, then returns a parameter that can go into the URL.
sub process_parameter {
    my ($arg) = @_;
    if ($debug) { print "entered process_parameter\n"; }
    if ( $arg =~ /^([^=]+)=(.*)$/sxm ) {
        return "$1=" . URI::Escape::uri_escape($2);
    }
    elsif ( $arg =~ /\A=/sxm ) {

        # We were passed something like '=foo' which is meaningless.
        die 'A parameter has no name. Did you misplace a space?';
    }
    else {
        local @ARGV;
        my $value;
        $value = prompt( "$arg: ", -e => '*' );
        return "$arg=$value";
    }
}

##################################################################################################################
#### Creating our UserAgent
##################################################################################################################

# Expects three arguments:
#   $username        - Defaults to 'root'
#   $password        - If you're not providing it, leave it false
#   $accesshash_name - a filename. Defaults to /root/.accesshash
# Returns an authenticated LWP user agent, or 0.
# WARNING: That behavior will almost certainly change.
sub auth_for_whm {
    my ( $username, $password, $accesshash_name ) = @_;
    if ($debug) { print "entered auth_for_whm\n"; }
    $username ||= 'root';

    my $useragent =
         simple_auth_via_hash( $username, $accesshash_name )
      or simple_auth_via_password( $username, $password )
      or die 'WHM-style authentication failed.';
    return $useragent;
}

sub auth_for_cp {
    my ( $username, $password, $accesshash_name ) = @_;
    if ($debug) { print "entered auth_for_cp\n"; }
    die 'cPanel API calls need a username.' unless $username;

    my $useragent = simple_auth_via_password( $username, $password );
    if ($useragent) {
        $security_token = '/';
        return $useragent;
    }
    if ($debug) { print "    Attempting cPanel user auth via root access hash.\n"; }

    my $accesshash = read_access_hash($accesshash_name);
    $useragent = get_security_token( $username, $accesshash );
    if ( !$useragent ) { die 'cPanel auth via hash failed.'; }
    return $useragent;
}

sub simple_auth_via_hash {
    my ( $username, $accesshash_name ) = @_;
    if ($debug) { print "entered simple_auth_via_hash\n"; }
    $accesshash_name ||= '/root/.accesshash';

    my $accesshash = read_access_hash($accesshash_name);
    return 0 unless $accesshash;
    if ($debug) { print "    Access hash used for authentication.\n"; }
    my $useragent = LWP::UserAgent->new(
        cookie_jar => HTTP::Cookies->new,
        ssl_opts   => { verify_hostname => 0, SSL_verify_mode => 0x00 },
    );
    $useragent->default_header( 'Authorization' => "WHM $username:$accesshash" );
    return $useragent;
}

sub simple_auth_via_password {
    my ( $username, $password ) = @_;
    if ($debug) { print "entered simple_auth_via_passwd\n"; }
    if ( !$username || !$password ) { return 0; }

    if ($debug) { print "    Password used for authentication.\n"; }
    my $useragent = LWP::UserAgent->new(
        cookie_jar => HTTP::Cookies->new,
        ssl_opts   => { verify_hostname => 0, SSL_verify_mode => 0x00 },
    );
    $useragent->default_header( 'Authorization' => 'BASIC ' . MIME::Base64::encode("$username:$password") );
    return $useragent;
}

# TODO: Need to make sure the access hash is valid.
sub read_access_hash {
    my ($accesshash_name) = @_;
    if ($debug) {
        print "entered read_access_hash\n";
        print "    read_access_hash got $accesshash_name\n";
    }
    my $accesshash;

    # TODO: This is probably the wrong thing to do.
    open my $accesshash_fh, '<', $accesshash_name or return undef;
    while (<$accesshash_fh>) {
        chomp;
        $accesshash .= $_;
    }
    close $accesshash_fh;
    if ($debug) {
        print "    access hash is " . length($accesshash) . " characters long.\n";
    }
    return $accesshash;
}

##################################################################################################################
#### Populating $security_token
##################################################################################################################

# Expects an API version and valid cPanel username.
#     MAKES A WHM API CALL
# to generate a user session, then returns the security token for that session.
# Currently does not check for or handle error conditions, like users that
# don't exist.
sub get_security_token {
    my ( $cpanel_username, $accesshash ) = @_;
    if ($debug) {
        print "entered get_security_token\n";
        print "    got username $cpanel_username\n";
    }
    return 0 unless $cpanel_username;
    return 0 unless $accesshash;

    # TODO: Maybe access hash is bad. Gotta deal with that.
    my $localuseragent = LWP::UserAgent->new(
        cookie_jar => HTTP::Cookies->new,
        ssl_opts   => { verify_hostname => 0, SSL_verify_mode => 0x00 },
    );
    $localuseragent->default_header( 'Authorization' => "WHM root:$accesshash" );

    my $request         = "/json-api/create_user_session?api.version=1&user=$cpanel_username&service=cpaneld";
    my $response        = $localuseragent->get( "$protocol://$hostname:2087$request", );
    my $decoded_content = $response->decoded_content;

    # Currently pointless exception handling.
    # At some point there may be conditions I want to catch.
    {
        local $@ = undef;
        $decoded_content = eval { JSON::decode_json($decoded_content); };
        if ($@) {
            if ($debug) {
                print "    decode_json inside get_security_token died. Here's the JSON:\n";
                print "    $decoded_content\n";
            }
            return 0;
        }
    }
    my $session_url = $decoded_content->{'data'}->{'url'};

    $session_url =~ m{(cpsess[^/]+)}sxm;
    $security_token = "$1/";
    if ($debug) {
        print "    session_url turned out to be $session_url\n";
        print "    security_token turned out to be $security_token\n";
    }

    my $useragent = LWP::UserAgent->new(
        cookie_jar => HTTP::Cookies->new,
        ssl_opts   => { verify_hostname => 0, SSL_verify_mode => 0x00 },
    );
    $response = $useragent->get($session_url);

    # global $security_token is now populated
    return $useragent;
}

##################################################################################################################
#### Assembling our request URL
##################################################################################################################

# Expects a hash of arguments. {
#   'protocol'       => defaults to http
#   'hostname'       => defaults to localhost
#   'api_class'      => one of uapi, api1, api2, whm0, or whm1
#   'security_token' => /cpsessXXXXXXXXXX/ or '' or undef
#   'module'         => the module within which the function you want resides
#   'function'       => the function you want to call
#   'username'       => for api1 and api2 calls, a username needs to be specified
#   'params_ref'     => an array of arguments to the API call.
# }
# Returns the URL of the API call, not including arguments to that call.
sub assemble_url {
    my %args = @_;

    if ($debug) {
        print "entered assemble_url\n";
        foreach ( sort keys %args ) { print "    assemble_url args $_ => " . $args{$_} . "\n"; }
    }

    my %parts = (
        'protocol'              => $args{'protocol'},
        'hostname'              => $args{'hostname'},
        'port'                  => whatis_port( $args{'api_class'}, $args{'protocol'} ),
        'json-api'              => is_jsonapi( $args{'api_class'} ),
        'security_token'        => $args{'security_token'},
        'execute'               => is_execute( $args{'api_class'} ),
        'cpanel'                => is_cpanel( $args{'api_class'} ),
        'user'                  => get_cpanel_userarg( $args{'api_class'}, $args{'username'} ),
        'cpanel_jsonapi_module' => is_cpanel_jsonapi_module( $args{'api_class'} ),
        'module'                => $args{'module'},
        'cpanel_jsonapi_func'   => is_cpanel_jsonapi_func( $args{'api_class'} ),
        'function'              => $args{'function'},
        'api_version'           => api_version( $args{'api_class'} ),
    );

    my $url;
    $url = "$parts{'protocol'}://$parts{'hostname'}:$parts{'port'}/";
    $url .= join q{},  @parts{qw/ security_token json-api execute cpanel user cpanel_jsonapi_module module cpanel_jsonapi_func function api_version /};
    $url .= join '&', @{ $args{'params_ref'} };

    return $url;
}

# These subroutines take the API class ( whm0, whm1, api1, api2, uapi ) and
# return a string if it needs to be in the URL. Empty is correct in some cases.
sub whatis_port {
    my ( $api_class, $protocol ) = @_;
    if ( $protocol eq 'https' ) {
        return $api_class =~ $whm_api_regex ? 2087 : 2083;
    }
    else {
        return $api_class =~ $whm_api_regex ? 2086 : 2082;
    }
}

sub is_jsonapi {
    my ($api_class) = @_;
    return $api_class =~ $uapi_regex ? q{} : 'json-api/';
}

sub is_execute {
    my ($api_class) = @_;
    return $api_class =~ $uapi_regex ? 'execute/' : q{};
}

sub is_cpanel {
    my ($api_class) = @_;
    return $api_class =~ $cpanel_api_regex ? 'cpanel?' : q{};
}

sub get_cpanel_userarg {
    my ( $api_class, $username ) = @_;
    return $api_class =~ $cpanel_api_regex ? "user=$username" : q{};
}

sub is_cpanel_jsonapi_module {
    my ($api_class) = @_;
    return $api_class =~ $cpanel_api_regex ? '&cpanel_jsonapi_module=' : q{};
}

sub is_cpanel_jsonapi_func {
    my ($api_class) = @_;
    return $api_class =~ $cpanel_api_regex ? '&cpanel_jsonapi_func=' : q{};
}

sub api_version {
    my ($api_class) = @_;
    $api_class = lc $api_class;
    my %results = (
        'whm0' => '?api.version=0&',
        'whm1' => '?api.version=1&',
        'api1' => '&cpanel_jsonapi_apiversion=1&',
        'api2' => '&cpanel_jsonapi_version=2&',
        'uapi' => '?'
    );
    return $results{$api_class};
}

sub help {

    my $help = <<'END';
USAGE:
    cpapi [options] API::Module::function argument=value

OPTIONS:
    -h, -help           Show this screen.

    -u, -username       Specify user on whose behalf you're making the call.
                        Necessary for UAPI, API1, and API2.
                        
    -p, -password       Prompt for password. We will ignore the password if
                        you try to pass it as an argument.
                        Currently only works for UAPI.

    -a, -accesshash     Specify alternate location for .accesshash. Default is
                        /root/.accesshash

    -d, -debug          Debugging output. Most subroutines announce entry, and
                        many print data that I managed to miscalculate
                        while developing the script.

                WARNING: Debug output has the potential to disclose
                sensitive information you put in your call.

AUTHENTICATION:
    For WHM calls, cpapi will try to use your access hash first. If you pass
    -p, it will prompt for your password, but still use your access hash if it
    can.

    For cPanel API calls, cpapi will use a password first if it's available.
    Otherwise, it will use root's access hash to generate a user session, then
    log in as the user and authenticate that way.

    There is no way to use root's password to make a cPanel API or UAPI call.
    Root's password can only authenticate for WHM API calls.

THE CALL NAME:
    The API class, module, and function name, are joined using ::. UAPI, API1,
    API2, WHM0, and WHM1 are valid API classes.

    The WHM APIs do not have namespacing, so they'll look like
    WHM0::function_name or similar.

    Please consult http://documentation.cpanel.net/ for lists of functions
    available through the five APIs.

ARGUMENTS:
    Arguments are specified as name=value. If you provide a value name without
    a value, cpapi will prompt you for its value; this way, you can avoid
    putting sensitive data into your Bash history.

    value= will not prompt. It will pass an empty string as the argument.

EXAMPLES:
    To change the FTP password for zoit@<david's primary domain>
    cpapi -u david UAPI::Ftp::passwd user=foo pass=fishface

    To change david's IP address to 1.2.3.4:
    cpapi WHM1::setsiteip user=david ip=1.2.3.4

    To add a 'site1' database for david to use:
    cpapi API2::MysqlFE::createdb db=david_site1

KNOWN PROBLEMS:
    User / Password authentication doesn't work for cPanel API1 / API2. A
    security token is required and the security token code isn't that smart
    yet.

END
    print $help;
    exit;
}
