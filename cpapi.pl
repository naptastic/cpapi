#!/usr/local/cpanel/3rdparty/bin/perl
# cpanel - cpapi.pl             Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited
use strict;

# use Getopt::Long;
use LWP::UserAgent;

# Because having a certificate installed on 'localhost' is kinda dumb,
# I'm not wasting time with HTTPS.
# use LWP::Protocol::https;
use HTTP::Cookies;
use IO::Prompt;
use JSON;
use Data::Dumper;

# Presented output should be presentable.
$JSON::pretty = 1;

my $username = 'root';
my $hostname = 'localhost';
my $protocol = 'http';
my $password = '';
# TODO: This cannot currently be overridden.
my $accesshash = '/root/.accesshash';
# Port will be determined from the call type.
my $port;

GetOptions(
    'username' => \$username,
#    Not until we have HTTPS working
#    'hostname' => \$hostname,
    'protocol' => \$protocol,
    'password' => \$password,
)

# Your access hash needs to be stored in /root/.accesshash. Eventually, this
# should become ~/.accesshash, but we don't have access hashes for users yet.

# Restricting scope for our filehandle, read in our access hash.
{
    open my $accesshash_fh, '<', '/root/.accesshash' or die 'Could not read /root/.accesshash. This is currently necessary for authentication.';
    while (<$accesshash_fh>) {
        chomp;
        $accesshash .= $_;
    }
    close $accesshash_fh;
}

# TODO: Need to make sure the access hash is valid.
my $useragent = LWP::UserAgent->new();
$useragent->default_header( 'Authorization' => 'WHM root:' . $accesshash, );

# ##################################################################################################################

=future

# $useragent->ssl_opts( verify_hostnames => 0); #brian d foy says "not so nice"

my @argv = @ARGV;
@ARGV = ();

my $uri = process_call( shift(@argv) );
$uri .= join( '&', ( '', map { process_parameter($_) } @argv ) );
print $uri;
print "\n";

my $response = $useragent->get($uri);
my $json     = JSON->new->pretty->encode( decode_json( $response->decoded_content ) );
print $json . "\n";
=cut

# ##################################################################################################################

# Expects the part of @ARGV that represents which API call we are making.
# Something with names separated by ::
# Returns the URL of the API call itself, minus arguments / parameters.
sub process_call_name {
    my ($call) = @_;
    my @call_parts = map { lcase $_ } split '::', $call;
    if ( $call_parts[0] eq 'uapi' ) {
        # TODO: This can go a few different ways:
        # 1. I am root, and providing a username: Create a user session.
        # 2. I provide a username and password: Use them.
        # 3. Insufficient authentication information: Die with a useful error message.
        create_session('nappy');
    }
    elsif ( $call_parts[0] eq 'whm0' ) {
        die "WHM API0 calls are not implemented yet (and will be implemented last). Thanks for playing!\n";
        $port = '2086';
    }
    elsif ( $call_parts[0] eq 'whm1' ) {
        return "${hostname}:2086/json-api/$call_parts[1]?api.version=1";
    }
    elsif ( $call_parts[0] eq 'whm1' ) {
        die "cPanel API1 calls are not implemented yet.\n";
        $port = '2082';
    }
    elsif ( $call_parts[0] eq 'whm2' ) {
        die "cPanel API2 calls are not implemented yet.\n";
        $port = '2082';
    }
    else {
        die 'The provided API version is not clear. Valid options are UAPI, API2 (for cPanel API2), and WHM1 (for WHM API1).';
    }

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
#   'protocol' => defaults to http (and really shouldn't be changed right now)
#   'hostname' => defaults to localhost (ditto)
#   'api_class' => one of UAPI, API1, API2, WHM0, or WHM1
#   'module' => the module within which the function you want resides
#   'function' => the function you want to call
#   'username' => for API1 and API2 calls, a username needs to be specified.
# }
# Returns the URL of the API call, not including arguments to that call.
sub assemble_url_noargs {
    my (%args) = @_;
    $args{'protocol'} ||= 'http';
    $args{'hostname'} ||= 'localhost';
    my $url;
    my %parts = {
        'protocol'              => $args{'protocol'},
        'hostname'              => $args{'hostname'},
        'port'                  => whatis_port( $args{'api_class'} ),
        'json-api'              => is_jsonapi( $args{'api_class'} ),
        'security_token'        => get_security_token( $args{'api_class'} ),
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

    return $url;
}

# Expects an API version in ( WHM0, WHM1, API1, API2, UAPI )
# Returns the appropriate port to use for this call.
sub whatis_port {
    my ($api_class) = @_;
    return $api_class =~ /^WHM.$/ ? 2086 : 2082;
}

# Expects an API version in ( WHM0, WHM1, API1, API2, UAPI )
# json-api will be part of the assembled URL, except for UAPI calls.
sub is_jsonapi {
    my ($api_class) = @_;
    return $api_class eq 'UAPI' ? '' : '/json-api/';
}

# Expects a valid cPanel username.
#     MAKES A WHM API CALL
# to generate a user session, then returns the security token for that session.
# Currently does not check for or handle error conditions, like users that
# don't exist.
sub get_security_token {
    my ($cpanel_username) = @_;
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

# These subroutines take the API class ( WHM0, WHM1, API1, API2, UAPI ) and
# return a string if it needs to be in the URL, or empty otherwise.
sub is_execute {
    my ($api_class) = @_;
    return $api_class eq 'UAPI' ? 'execute/' : '';
}

sub is_cpanel {
    my ($api_class) = @_;
    return $api_class =~ /^API.$/ ? 'cpanel?' : '';
}

sub get_cpanel_userarg {
    my ( $api_class, $username ) = @_;
    return $api_class =~ /^API.$/ ? "user=$username" : '';
}

sub is_cpanel_jsonapi_module {
    my ($api_class) = @_;
    return $api_class =~ /^API.$/ ? '&cpanel_jsonapi_module=' : '';
}

sub is_cpanel_jsonapi_func {
    my ($api_class) = @_;
    return $api_class =~ /^API.$/ ? '&cpanel_jsonapi_func=' : '';
}

sub api_version {
    my ($api_class) = @_;
    my %results = {
        'WHM0' => '?api.version=0',
        'WHM1' => '?api.version=1',
        'API1' => '&cpanel_jsonapi_version=1',
        'API2' => '&cpanel_jsonapi_version=2',
        'UAPI' => '',
    };
    return $results{$api_class};
}
