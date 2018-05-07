# tmpnb
Jupyter tmpnb server

## Boise State Research Computing

This server provides on-demand docker containers for students and faculty who
need pre-defined programming environments.  The containers all make use of
Jupyter notebooks and slight variations (see docker/\*/Dockerfile for recipes.

## Configuration

The server works off of a `json`configuration file that has parameters for
access and container options.  Below is an annotated example (comments are not
allowed in the actual configuaration file).

    {
      // asset_path specifies the directory for the html templates, static
      // files, and oauth2 id and secret (named token and secret respectively)
      "asset_path": "/opt/src/github.com/bsurc/tmpnb/assets",
      // container_lifetime specifies how long the container should
      // approximately live after the last access.  The format follows Go's
      // time.Duration formatting:
      //
      // (https://golang.org/pkg/time/#ParseDuration)
      //
      // Such as 10m for 10 minutes, 1h for 1 hour, etc.  The largest time unit
      // is an hour.
      "container_lifetime": "10m",
      // disable_jupyter_auth disables a security feature in the notebook
      // limiting access.  It sometimes causes issues when the
      // containers/notebooks are started and it asks for a token.  If you
      // encounter this issue, set this to true.  The server has session
      // information as well, so this is mostly redundant.
      "disable_jupyter_auth": false,
      // enable_acme allows TLS support via letsencrypt.org.
      "enable_acme": false,
      // enable_scp should be false (in development)
      "enable_csp": false,
      // enable_docker_push should be false (in development)
      "enable_docker_push": false,
      // enable_pprof allows introspection via the Go net/http/pprof
      // profiling (https://golang.org/pkg/net/http/pprof/).  It registers the
      // endpoints explicitly.
      "enable_pprof": true,
      // enable_stats exposes the endpoint /stats with various metrics such
      // as number of containers, free memory, etc.
      "enable_stats": true,
      // github_repo is used for pulling and building images in real time.
      // Currently unused.
      "github_repo": "bsurc/tmpnb",
      // image_regexp specifies what docker images to expose, for example for
      // BSU jupyter notebooks:
      //
      // boisestate/[a-zA-Z0-9]+-notebook
      //
      // or similar
      "image_regexp": ".*",
      // access_logfile tracks remote access.  "" -> stdout
      "access_logfile": "",
      // log_logfile tracks some activity on the server and pool
      "logfile": "",
      "max_containers": 100,
      // rotate_logs specifies whether or not to manually rotate logs (I need
      // to read up on logrotate)
      "rotate_logs": false,
      // http_redirect redirects all http -> https if TLS is used
      "http_redirect": false,
      // persistent allows users to leave a notebook and come back later.  The
      // image is saved.  OAuth2 must be enabled so the image can be tied to a
      // specific user.
      "persistent": false,
      // port is the port to listen on, if port is "", either 80 or 443 is used
      // depending on HTTP or HTTPS
      "port": ":8888",
      // host is used for OAuth callbacks and a handful of redirects.
      "host": "127.0.0.1",
      // tls_cert is the TLS certificate path.  Both tls_cert and tls_key is
      // needed to enable TLS.
      "tls_cert": "",
      // tls_key is the TLS certificate path.  Both tls_cert and tls_key is
      // needed to enable TLS.
      "tls_key": "",
      // oauth_config is to enable OAuth2.  Currently only google is OAuth2 is
      // available.  If other endpoints are needed, please file an issue.
      "oauth_confg": {
        // whitelist specifies access for specific emails, such as
        // kyleshannon@boisestate.edu
        "whitelist": [
        ],
        // match allows a regular expression match such as:
        // ^.+@u.boisestate.edu
        // for undergraduate BSU students or 
        // ^.+@(u\.)?boisestate.edu$
        //  for any BSU email
        "match": ""
      }
    }


