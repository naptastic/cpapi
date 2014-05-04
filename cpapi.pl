#!/usr/local/cpanel/3rdparty/bin/perl
# cpanel - cpapi.pl             Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited
use strict;

use LWP::UserAgent;

# Because having a certificate installed on 'localhost' is kinda dumb,
# I'm not wasting time with HTTPS.
# use LWP::Protocol::https;
use HTTP::Cookies;
use IO::Prompt;
use Data::Dumper;

# Presented output should be presentable.
use JSON;
$JSON::pretty = 1;

use Getopt::Long;

my $username        = 'root';
my $hostname        = 'localhost';
my $protocol        = 'http';
my $password        = '';
my $accesshash_name = '/root/.accesshash';

my $call_name;
my @call_params;

# Port will be determined from the call type.
my $port;
my $api_class;
my $module;
my $function;

GetOptions(
    'username=s'   => \$username,
    'u=s'          => \$username,
    'password'     => \$password,
    'p'            => \$password,
    'accesshash=s' => \$accesshash_name,
    '<>'           => \&process_non_option,
);

sub process_non_option {
    my ( $opt_name, $opt_value ) = @_;
    if ( $opt_name =~ /::/ ) {
        ( $port, $api_class, $module, $function ) = process_call_name($opt_name);
    }
    elsif ( $opt_name =~ /=/ ) {
        push @call_params, process_parameter($opt_name);
    }
    else {
        print "Non-option name is $opt_name and value is $opt_value\n";
    }
}

my $accesshash = read_access_hash($accesshash_name);


my $url = assemble_url(
    'protocol'   => $protocol,
    'hostname'   => $hostname,
    'api_class'  => $api_class,
    'module'     => $module,
    'function'   => $function,
    'username'   => $username,
    'params_ref' => \@call_params,
);

print $url;

# my $useragent = LWP::UserAgent->new();
# $useragent->default_header( 'Authorization' => 'WHM root:' . $accesshash, );

# ##################################################################################################################

# Expects the part of @ARGV that represents which API call we are making.
# Something with names separated by ::
# Returns port, API class, module, and function name.
sub process_call_name {
    my ($call) = @_;
    my @call_parts = map { lc } split '::', $call;
    my $port;
    my $api_class;
    my $module;
    my $function;
    if ( $call_parts[0] eq 'uapi' ) {
        $port      = '2082';
        $api_class = unshift @call_parts;
        $function  = pop @call_parts;
        $module    = join( '', @call_parts );
    }
    elsif ( $call_parts[0] eq 'whm0' ) {
        $port = '2086';
        ( $api_class, $module, $function ) = @call_parts;
    }
    elsif ( $call_parts[0] eq 'whm1' ) {
        $port = '2086';
        ( $api_class, $module, $function ) = @call_parts;
    }
    elsif ( $call_parts[0] eq 'api1' ) {
        $port = '2082';
        ( $api_class, $module, $function ) = @call_parts;
    }
    elsif ( $call_parts[0] eq 'api2' ) {
        $port = '2082';
        ( $api_class, $module, $function ) = @call_parts;
    }
    else {
        die 'API version is not clear. Use UAPI, API1, API2, WHM0, or WHM1.';
    }
    return ( $port, $api_class, $module, $function );
}

# Expects a list of parameters that were passed to the program.
# It only handles parameters for the API call. It will not handle
# call names or other possibilities.
sub process_parameter {
    my ($arg) = @_;
    if ( $arg =~ /([^=]+)=(.*)/ ) {
        return $arg;
    }
    elsif ( $arg =~ /^=/ ) {

        # We were passed something like '=foo' which is meaningless.
        die "A parameter has no name. Did you misplace a space?\n";
    }
    else {
        my $value;
        $value = prompt("$arg: ");
        return "$arg=$value";
    }
}

# Expects a hash of arguments. {
#   'protocol'      => defaults to http (and really shouldn't be changed right now)
#   'hostname'      => defaults to localhost (ditto)
#   'api_class'     => one of uapi, api1, api2, whm0, or whm1
#   'module'        => the module within which the function you want resides
#   'function'      => the function you want to call
#   'username'      => for api1 and api2 calls, a username needs to be specified
#   'params_ref'    => an array of arguments to the API call.
# }
# Returns the URL of the API call, not including arguments to that call.
sub assemble_url {
    my (%args) = @_;
    $args{'protocol'} ||= 'http';
    $args{'hostname'} ||= 'localhost';
    my $url;
    my %parts = {
        'protocol'              => $args{'protocol'},
        'hostname'              => $args{'hostname'},
        'port'                  => whatis_port( $args{'api_class'} ),
        'json-api'              => is_jsonapi( $args{'api_class'} ),
        'security_token'        => get_security_token( $args{'api_class'}, $args{'username'} ),
        'execute'               => is_execute( $args{'api_class'} ),
        'cpanel'                => is_cpanel( $args{'api_class'} ),
        'user'                  => get_cpanel_userarg( $args{'api_class'}, $args{'username'} ),
        'cpanel_jsonapi_module' => is_cpanel_jsonapi_module( $args{'api_class'} ),
        'module'                => $args{'module'},
        'cpanel_jsonapi_func'   => is_cpanel_jsonapi_func( $args{'api_class'} ),
        'func'                  => $args{'func'},
        'api_version'           => api_version( $args{'api_class'} ),
    };
    $url = "$parts{'protocol'}://$parts{'hostname'}:$parts{'port'}";
    $url .= join '', @args{qw/ json-api security_token executecpanel user cpanel_jsonapi_module module cpanel_jsonapi_func func api_version /};
    $url .= '?' . join '&', @{$args{'params_ref'}};

    return $url;
}

# TODO: Need to make sure the access hash is valid.
sub read_access_hash {
    my ($accesshash_name) = @_;
    my $accesshash;

    # TODO: This is probably the wrong thing to do.
    return '' unless -e $accesshash_name;
    open my $accesshash_fh, '<', $accesshash_name or return '';
    while (<$accesshash_fh>) {
        chomp;
        $accesshash .= $_;
    }
    close $accesshash_fh;
    return $accesshash;
}

# Expects an API version in ( whm0, whm1, api1, api2, uapi )
# Returns the appropriate port to use for this call.
sub whatis_port {
    my ($api_class) = @_;
    return $api_class =~ /^whm.$/ ? 2086 : 2082;
}

# Expects an API version in ( whm0, whm1, api1, api2, uapi )
# json-api will be part of the assembled URL, except for UAPI calls.
sub is_jsonapi {
    my ($api_class) = @_;
    return $api_class eq 'uapi' ? '' : '/json-api/';
}

# Expects an API version and valid cPanel username.
#     MAKES A WHM API CALL
# to generate a user session, then returns the security token for that session.
# Currently does not check for or handle error conditions, like users that
# don't exist.
sub get_security_token {
    my ( $api_class, $cpanel_username ) = @_;
    return '' unless $api_class eq 'uapi';

    # TODO: Maybe access hash is bad. Gotta deal with that.

    my $useragent = LWP::UserAgent->new(
        cookie_jar            => HTTP::Cookies->new,
        requests_redirectable => []
    );
    $useragent->default_header( 'Authorization' => 'WHM root:' . $accesshash, );

    my $request  = "/json-api/create_user_session?api.version=1&user=${cpanel_username}&service=cpaneld";
    my $response = $useragent->post( "${hostname}:2086" . $request, );

    my $decoded_content = decode_json( $response->decoded_content );
    my $session_url     = $decoded_content->{'data'}->{'url'};

    # LWP will bomb out with a certificate problem if we use HTTPS, so we have to use plain HTTP.
    $session_url =~ s/https:/http:/;
    $session_url =~ s/:2083/:2082/;

    $response = $useragent->get($session_url);
    my ($security_token) = $response->header('refresh') =~ m{(cpsess[^/]+)};
    return "/$security_token/";
}

# These subroutines take the API class ( whm0, whm1, api1, api2, uapi ) and
# return a string if it needs to be in the URL, or empty otherwise.
sub is_execute {
    my ($api_class) = @_;
    return $api_class eq 'uapi' ? 'execute/' : '';
}

sub is_cpanel {
    my ($api_class) = @_;
    return $api_class =~ /^api.$/ ? 'cpanel?' : '';
}

sub get_cpanel_userarg {
    my ( $api_class, $username ) = @_;
    return $api_class =~ /^api.$/ ? "user=$username" : '';
}

sub is_cpanel_jsonapi_module {
    my ($api_class) = @_;
    return $api_class =~ /^api.$/ ? '&cpanel_jsonapi_module=' : '';
}

sub is_cpanel_jsonapi_func {
    my ($api_class) = @_;
    return $api_class =~ /^api.$/ ? '&cpanel_jsonapi_func=' : '';
}

sub api_version {
    my ($api_class) = @_;
    my %results = {
        'whm0' => '?api.version=0',
        'whm1' => '?api.version=1',
        'api1' => '&cpanel_jsonapi_version=1',
        'api2' => '&cpanel_jsonapi_version=2',
        'uapi' => '',
    };
    return $results{$api_class};
}
