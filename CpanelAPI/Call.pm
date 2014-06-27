package CpanelAPI::Call;

my $uapi_regex       = qr/^uapi$/i;
my $whm_api_regex    = qr/^whm[01]$/i;
my $cpanel_api_regex = qr/^api[12]$/i;

# New returns a call object that can be 'done'
# do_the_thing makes the call and returns... I'm not sure what yet.

# Expects:
# $args = {
#     connection => a CpanelAPI::Connection object
#     api_class  => one of 'uapi', 'whm0', 'whm1', 'api1', or 'api2'
#     module     => the module in which the API call you're making lives
#     function   => the function you want to call
#     params_ref => a reference to an array of pre-formatted parameters, like
#          [ 'argument=percent_encoded_value',]
# }
sub new {
    my ( $class, $args ) = @_;
    my $connection = $args->{'connection'};
    my $parts      = (
        'protocol'              => $connection->{'protocol'},
        'hostname'              => $connection->{'hostname'},
        'port'                  => _whatis_port( $args->{'api_class'} ),
        'json-api'              => _is_jsonapi( $args->{'api_class'} ),
        'execute'               => _is_execute( $args->{'api_class'} ),
        'cpanel'                => _is_cpanel( $args->{'api_class'} ),
        'user'                  => _get_cpanel_userarg( $args->{'api_class'}, $connection->{'username'} ),
        'cpanel_jsonapi_module' => _is_cpanel_jsonapi_module( $args->{'api_class'} ),
        'module'                => $args->{'module'},
        'cpanel_jsonapi_func'   => _is_cpanel_jsonapi_func( $args->{'api_class'} ),
        'function'              => $args->{'function'},
        'api_version'           => _api_version( $args->{'api_class'} ),
    );

    my $url;
    $url = "$parts{'protocol'}://$parts{'hostname'}:$parts{'port'}/";
    $url .= join '',  @parts{qw/ security_token json-api execute cpanel user cpanel_jsonapi_module module cpanel_jsonapi_func function api_version /};
    $url .= join '&', @{ $args{'params_ref'} };

    my $self = {
        'connection' => $connection,
        'url'        => $url,
    };
    return bless $self, $class;
}

sub do_call {
    my ( $self, $args ) = @_;
    my $connection = $self->{'connection'};
    my $useragent  = $connection->{'useragent'};
}

# These subroutines take the API class ( whm0, whm1, api1, api2, uapi ) and
# return a string if it needs to be in the URL. Empty is correct in some cases.

sub _whatis_port {
    my ($api_class) = @_;
    return $api_class =~ $whm_api_regex ? 2087 : 2083;
}

sub _is_jsonapi {
    my ($api_class) = @_;
    return $api_class =~ $uapi_regex ? '' : 'json-api/';
}

sub _is_execute {
    my ($api_class) = @_;
    return $api_class =~ $uapi_regex ? 'execute/' : '';
}

sub _is_cpanel {
    my ($api_class) = @_;
    return $api_class =~ $cpanel_api_regex ? 'cpanel?' : '';
}

sub _get_cpanel_userarg {
    my ( $api_class, $username ) = @_;
    return $api_class =~ $cpanel_api_regex ? "user=$username" : '';
}

sub _is_cpanel_jsonapi_module {
    my ($api_class) = @_;
    return $api_class =~ $cpanel_api_regex ? '&cpanel_jsonapi_module=' : '';
}

sub _is_cpanel_jsonapi_func {
    my ($api_class) = @_;
    return $api_class =~ $cpanel_api_regex ? '&cpanel_jsonapi_func=' : '';
}

sub _api_version {
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
