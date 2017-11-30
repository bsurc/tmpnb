## Persistent Notebooks

### Summary

The temporary Jupyter notebooks seem to be effective for teaching and
experimenting with coding.  Currently, the containers life cycle is:

0. User navigates to the server
0. User provides OAuth login credentials (optional)
0. Server allows or denies access (optional)
0. Server lists available images
0. User selects which image to create a container with
0. Server checks if the image is valid (exists, and matches a filter)
0. Server creates a container with the image analogous to `docker run
   image_name:tag`
0. Server creates a reverse proxy for the image using a random path
0. Server waits for a specified period of time, pinging the containers landing
   page
0. When the server receives a response, it returns to the client
0. The client checks for the ping as well, and when it receives a response,
   allows the user to click a link to the container
0. Server acts as a proxy for the user and the container, renewing a timeout on
   each request
0. After a specified duration, the container is stopped, and then removed
   permanently

### Need for Persistence

In some instances, users have requested a persistent state.  This would allow
students to return to the state they left the container in when it last
expired.  This would allow a smoother workflow for both classes and user
groups.

### Design

In order to allow for persistence, the user must be identifiable, and must be
authenticated through OAuth.  If available, and desired, the last snapshot of
the image will be loaded for that user.  If no snapshot exists, or the user
wishes to have a clean slate, a new container will be created from the base
image.

When the container expires, if persistence is enabled, the changes are written
back to the image and that image is the new persistent image.

The new life cycle is:

0. User navigates to the server
0. User provides OAuth login credentials
0. Server allows or denies access
0. Server lists available _base_ images
0. User selects which image to create a container with, and specifies whether
   or not to turn on persistence
0. Server checks if the image is valid, whether a persistent image exists, and
   if the user email matches the image tag
0. Server creates a container with the image analogous to `docker run
   image_name:tag or image_name:bsu_email@boisestate.edu`
0. Server creates a reverse proxy for the image using a random path
0. Server waits for a specified period of time, pinging the containers landing
   page
0. When the server receives a response, it returns to the client
0. The client checks for the ping as well, and when it receives a response,
   allows the user to click a link to the container
0. Server acts as a proxy for the user and the container, renewing a timeout on
   each request
0. After a specified duration, the container is stopped
0. If persistence is enabled, the container is written to the persistent image,
   overwriting the old persistent image
0. The container is removed

### Guarantees

There are no guarantees on persistence.  Images may be lost, removed, etc.
without notice.  Users should back up there data and code outside of the
container.  It is meant to give the user a stable development platform, not a
data repository.  `git` is available on the containers, and can be used.

### Limitations

The persistence model word force some limitations.  Each user could only have
one persistent image per root image.  This would limit disk usage and makes the
implementation simpler and cleaner.

The users will also be limited to a single running instance of a container.  If
they request a new container, and another, initial instance is running, the
user will be redirected to the running container.

The contents of the notebooks isn't monitored in anyway.  If someone is storing
malicious or illegal information, it is on our server(s).  We would have to
reserve the right to remove any such data without notice.  This is obvious, but
may have other implications like disclaimers or a full policy written up.

Care must be taken to have a good base image, as we can't pull in changes after
the persistent image is created (I think).

#### Technical

The current server(s) are handling decent loads (~60 containers, not all in
use).  There will be little overhead for matching persistent images with users.
Some care will have to be taken to not allow more than one container is open
for a user.  Non-persistent images will be allowed to live side by side with
the single persistent image.














