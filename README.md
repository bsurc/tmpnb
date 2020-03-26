# tmpnb Jupyter tmpnb server

## Boise State Research Computing

This server provides on-demand docker containers for students and faculty who
need pre-defined programming environments.  The containers all make use of
Jupyter notebooks and slight variations (see docker/\*/Dockerfile for recipes.

## Configuration

See `tmpnb -help` for a list of configurations, a detailed description follows.

`-acme`: This uses letsencrypt to create and install certificates for TLS, with
automatic renewals.

`-addr`: Specifiy the service/port/address to listen on.  :8888 is the default
for localhost/debugging.

`-assets`: Path to the ./assets folder in this directory.  Keys, templates, and
other ancillary data are stored there.

`-host`: The name of the host to generate link names.  Links internal to the
notebook are also generated using this host name.

`-imageregexp`: A regular expression for the image names allowed to be created
and deployed.

`-info`: Print general info and exit.

`-jupyterauth`: Enable the internal jupyter authentication.

`-lifetime`: Specify the lifetime of the container after the a specific idle
time.  Durations are specified using Go duration format (10m30s -> ten minutes
and thirty seconds, 1h30m30s -> one hour, thirty minutes and thirty seconds,
etc.)

`-maxcontainers`: The maximum number of container instances that can be started
on the server.  All requests for new servers will be denied until a slot opens
up from a reclaimed container.  

`-mintls`: The minimum version of TLS to use
for https.

`-oauthregexp`: Enable OAuth2 for use with google addresses.  Emails must match
the regexp provided for access.

`-oauthwhite`: Enable OAuth2 and allow only specific google related emails
access.

`-persist`: Enable persistent data.  This uses OAuth2 identities to write
containers back to the system before reclaiming the container.  OAuth2 must be
enabled to match users to specific containers.  This feature is experimental,
and not guaranteed to work.

`-pprof`: Enable and expose the net/http/pprof handlers for debugging.

`-stats`: Enable the /stats page to inspect live containers and resource usage.
