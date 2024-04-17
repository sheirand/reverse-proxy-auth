- `docker build -t envoy:v1 .`
- `docker run -d --name envoy -p 8080:8080 envoy:v1`
- send requests to localhost:8080 (or other if config changes)
- take a look at good example of Envoy configuration yaml file with comments:
````
# Resources loaded at boot, rather than dynamically via APIs.
# https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/bootstrap/v3/bootstrap.proto#envoy-v3-api-msg-config-bootstrap-v3-bootstrap-staticresources
static_resources:
  # A listener wraps an address to bind to and filters to run on messages on that address.
  # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener.proto#envoy-v3-api-msg-config-listener-v3-listener
  listeners:
    # The address of an interface to bind to. Interfaces can be sockets, pipes, or internal addresses.
    # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/address.proto#envoy-v3-api-msg-config-core-v3-address
    - address:
        # This address is for a network socket, with an IP and a port.
        # WARNING: Never use JWT over HTTP in production, ALWAYS use HTTPS.
        # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/address.proto#envoy-v3-api-msg-config-core-v3-socketaddress
        socket_address:
          # The value 0.0.0.0 indicates that all interfaces will be bound to.
          address: 0.0.0.0
          # The IP port number to bind to.
          port_value: 8080
      # Filter chains wrap several related configurations, e.g. match criteria, TLS context, filters, etc.
      # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener_components.proto#envoy-v3-api-msg-config-listener-v3-filterchain
      filter_chains:
        # An ordered list of filters to apply to connections.
        # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener_components.proto#envoy-v3-api-msg-config-listener-v3-filter
        - filters:
          - name: envoy.filters.network.http_connection_manager
            # A generic configuration whose fields vary with its "@type".
            typed_config:
              # The HttpConnectionManager filter converts raw data into HTTP messages, logging,
              # tracing, header manipulation, routing, and statistics.
              # https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_connection_management#arch-overview-http-conn-man
              # https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#extension-envoy-filters-network-http-connection-manager
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              # The human readable prefix used when emitting statistics.
              stat_prefix: ingress_http

              # The static routing table used by this filter. Individual routes may also add "rate
              # limit descriptors", essentially tags, to requests which may be referenced in the
              # "http_filters" config.
              # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route.proto#envoy-v3-api-msg-config-route-v3-routeconfiguration
              route_config:
                name: local_route
                # An array of virtual hosts which will compose the routing table.
                # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-msg-config-route-v3-virtualhost
                virtual_hosts:
                  - name: backend
                    # A list of domains, e.g. *.foo.com, that will match this virtual host.
                    domains:
                      - "*"
                    # A list of routes to match against requests, the first one that matches will be used.
                    # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-msg-config-route-v3-route
                    routes:
                      # The conditions that a request must satisfy to follow this route.
                      # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-msg-config-route-v3-routematch
                      - match:
                          # A match against the beginning of the :path pseudo-header.
                          prefix: "/"
                        # The routing action to take if the request matches the conditions.
                        # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-msg-config-route-v3-routeaction
                        route:
                          host_rewrite_literal: www.envoyproxy.io
                          cluster: service_envoyproxy_io
              # Individual filters applied by the HTTP Connection Manager.
              # https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto#envoy-v3-api-msg-extensions-filters-network-http-connection-manager-v3-httpfilter
              http_filters:
                # The filter that reads the JWT is a the HTTP rather than the TCP level.
                # https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/jwt_authn_filter
                - name: envoy.filters.http.JwtAuthentication
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                    providers:
                      # Each JWT authentication provider has a name to be used in routing rules.
                      provider_funnel:
                        # The name of the entity that is providing the JWT.
                        issuer: https://auth.funnel-labs.io/auth/realms/funnel
                        # Obtain a JSON Web Key Set from a remove server for JWT validation.
                        remote_jwks:
                          http_uri:
                            uri: https://auth.funnel-labs.io/auth/realms/funnel/protocol/openid-connect/certs
                            cluster: funnel_auth_cluster
                            timeout: 1s
                          cache_duration:
                            seconds: 300
                        # Extract the JWT base64 payload and include it in a header.
                        forward_payload_header: x-jwt-payload
                    rules:
                      # No authentication provider is specified, thus, no authentication happens.
                      - match:
                          prefix: /docs
                      # Aside from the /docs URL, require JWT authentication using the provider name.
                      - match:
                          prefix: /
                        requires:
                          provider_name: provider_funnel
                # The router filter performs HTTP forwarding with optional logic for retries, statistics, etc.
                # https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/router/v3/router.proto#extension-envoy-filters-http-router
                # https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/router_filter#config-http-filters-router
                - name: envoy.filters.http.router
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  # Configurations for logically similar upstream hosts, called clusters, that Envoy connects to.
  # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-msg-config-cluster-v3-cluster
  clusters:
    # A cluster allowing communication with the Funnel authentication service.
    - name: funnel_auth_cluster
      type: STRICT_DNS
      connect_timeout: 500s
      load_assignment:
        cluster_name: funnel_auth_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: auth.funnel-labs.io
                      port_value: 443
      transport_socket:
        name: envoy.transport_sockets.tls
    - name: service_envoyproxy_io
      # The cluster type, in this case, discover the target via a DNS lookup.
      # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#envoy-v3-api-enum-config-cluster-v3-cluster-discoverytype
      type: LOGICAL_DNS
      connect_timeout: 500s
      dns_lookup_family: V4_ONLY
      # For endpoints that are part of the cluster, determine how requests are distributed.
      # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/endpoint/v3/endpoint.proto#envoy-v3-api-msg-config-endpoint-v3-clusterloadassignment
      load_assignment:
        cluster_name: service_envoyproxy_io
        endpoints:
          # A list of endpoints that belong to this cluster.
          # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/endpoint/v3/endpoint_components.proto#envoy-v3-api-msg-config-endpoint-v3-localitylbendpoints
          - lb_endpoints:
              # A single endpoint, it's load-balancing weight, etc.
              # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/endpoint/v3/endpoint_components.proto#envoy-v3-api-msg-config-endpoint-v3-lbendpoint
              - endpoint:
                  address:
                    socket_address:
                      address: www.envoyproxy.io
                      port_value: 443
      # A customized transport socket, in this case, with TLS enabled.
      # https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto#envoy-v3-api-msg-config-core-v3-transportsocket
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          # https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          # Server Name Indication, the server being contacted in step 1 of the TLS handshake.
          sni: www.envoyproxy.io
```