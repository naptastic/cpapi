package CpanelAPI::Connection;

use HTTP::Tiny;
use HTTP::Cookies;

my $uapi_regex       = qr/^uapi$/i;
my $whm_api_regex    = qr/^whm[01]$/i;
my $cpanel_api_regex = qr/^api[12]$/i;

# In the context of this module, a connection object does not actually
# represent a connection. (The API is stateless, so "connection" is
# meaningless.) Rather, it represents connection and authentication data that
# will be used to interact with the API.
#
# It's not a User Agent. It's not a truck. It's not a series of tubes. And it's not people.

# Expects:
# $args = {
#     hostname = Can be a hostname or IP address,
#     username = cPanel or WHM username,
#     password = User's password or '' or undef,
#     accesshash = Root or reseller access hash or '' or undef
# }
sub new {
    my ( $class, $args ) = @_;
    my $self = {
        'hostname'       => $args{'hostname'},
        'username'       => $args{'username'},
        'password'       => $args{'password'},
        'accesshash'     => $args{'accesshash'},
        'protocol'       => 'https',
        'security_token' => '/',
        'useragent'      => _make_useragent($args),
    };
    return bless $self, $class;
}

# This allows dropping privileges from root or a reseller to a cPanel user.
# If a reseller uses this, then the reseller must own the account. Root can
# use this for any account.
#
# This is the method for accessing cPanel functions if the only authentication
# you have is root or reseller.
#
# Expects:
# $args = {
#     username => the cPanel user for whom you want a session created,
#     connection => the root or reseller-authorized connection,
# }
sub create_user_session {
    my ( $self, $args ) = @_;
    my $cpanel_username = $args->{'username'};
    my $accesshash      = $args->{'connection'}->{'accesshash'};

    # Obviously... create a user session and return that connection object.
    # TODO: Convert this to a CpanelAPI::Call thingy. This is nothing but duplicated code.
    my $localuseragent = HTTP::Tiny->new(
        cookie_jar      => HTTP::Cookies->new,
        default_headers => { 'Authorization' => 'WHM root:' . $accesshash, },
    );

    my $request  = "/json-api/create_user_session?api.version=1&user=$cpanel_username&service=cpaneld";
    my $response = $localuseragent->post( "$protocol://$hostname:2087$request", );
    my $decoded_content;

    # Currently pointless exception handling.
    # At some point there may be conditions I want to catch.
    {
        local $@;
        eval { $decoded_content = decode_json( $response->{content} ); };
        if ($@) {
            print Dumper($response);
            return 0;
        }
    }
    my $session_url = $decoded_content->{'data'}->{'url'};

    $session_url =~ m{(cpsess[^/]+)};
    $security_token = "$1/";
    if ($debug) { print "    security_token turned out to be $security_token\n"; }

    my $useragent = HTTP::Tiny->new( cookie_jar => HTTP::Cookies->new, );
    $response = $useragent->get($session_url);

    # global $security_token is now populated
    return $useragent;

}

# Below here goes all the code to choose the authentication method, and add
# supporting data to $self.
# I don't currently have this code, because it's in a newer branch than I have
# on this workstation right now.

sub _make_useragent {
    if ( $args{'context'} =~ $whm_api_regex ) {
        $useragent = _auth_for_whm( $username, $password, $accesshash_name );
    }
    elsif ( $api_class =~ $cpanel_api_regex || $api_class =~ $uapi_regex ) {
        $useragent = _auth_for_cp( $username, $password, $accesshash_name );
    }
    return $useragent;
}

# Expects three arguments:
#   $username        - Defaults to 'root'
#   $password        - If you're not providing it, leave it false
#   $accesshash_name - a filename. Defaults to /root/.accesshash
# Returns an authenticated HTTP::Tiny user agent, or 0.
# WARNING: That behavior will almost certainly change.
sub _auth_for_whm {
    my ( $username, $password, $accesshash_name ) = @_;
    if ($debug) { print "entered auth_for_whm\n"; }
    $username ||= 'root';

    my $useragent =
         simple_auth_via_hash( $username, $accesshash_name )
      or simple_auth_via_password( $username, $password )
      or die "WHM-style authentication failed.\n";
    return $useragent;
}

sub _auth_for_cp {
    my ( $username, $password, $accesshash_name ) = @_;
    if ($debug) { print "entered auth_for_cp\n"; }
    die "cPanel API calls need a username.\n" unless $username;

    my $useragent = simple_auth_via_password( $username, $password );
    if ($useragent) {
        $security_token = '/';
        return $useragent;
    }
    if ($debug) { print "    Attempting cPanel user auth via root access hash.\n"; }

    my $accesshash = read_access_hash($accesshash_name);
    $useragent = get_security_token( $username, $accesshash );
    if ( !$useragent ) { die 'cPanel auth via hash failed.\n'; }
    return $useragent;
}

sub _simple_auth_via_hash {
    my ( $username, $accesshash_name ) = @_;
    if ($debug) { print "entered simple_auth_via_hash\n"; }
    $accesshash_name ||= '/root/.accesshash';

    my $accesshash = read_access_hash($accesshash_name);
    return 0 unless $accesshash;
    if ($debug) { print "    Access hash used for authentication.\n"; }
    my $useragent = HTTP::Tiny->new(
        cookie_jar      => HTTP::Cookies->new,
        default_headers => { 'Authorization' => "WHM $username:$accesshash", },
    );
    return $useragent;
}

sub _simple_auth_via_password {
    my ( $username, $password ) = @_;
    if ($debug) { print "entered simple_auth_via_passwd\n"; }
    if ( !$username || !$password ) { return 0; }

    if ($debug) { print "    Password used for authentication.\n"; }
    my $useragent = HTTP::Tiny->new(
        cookie_jar      => HTTP::Cookies->new,
        default_headers => { 'Authorization' => 'BASIC ' . MIME::Base64::encode("$username:$password"), }
    );
    return $useragent;
}

# TODO: Need to make sure the access hash is valid.
sub _read_access_hash {
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
