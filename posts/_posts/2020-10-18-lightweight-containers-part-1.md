---
title: "Implementing fast lightweight containers in Go with bst and btrfs (Part 1)"
---

# Containers, namespaces, and execution model

This is the first part of a series to build a toy container system for fun.
In this segment, we'll work on the initial setup to run arbitrary commands
on an Alpine Linux image.

Containers are not exactly trivial to implement from scratch. It takes a lot
of work to understand and use namespaces, and getting the semantics right is
even harder -- so let's do it! What could possibly go wrong?

Snark aside, we'll try to implement a toy container system in this article,
and see what we learn. However, the fact remains that the namespacing part
alone would probably take months to do, so what can we do? Well, it turns out
that at Arista Networks, we released a tool called [bst][bst], which makes
that work significantly easier. It is still not completely trivial, but it
becomes possible to write a toy container system over a few days.

What do we want out of a container system? A few things come to mind:

* We need it to manage container images.
* We need it to manage per-user containers.
* We'd like it to be fast.
* We'd like it to be usable unprivileged (i.e. the user should not have to use `sudo`)

## The setup

For this setup, we'll be needing a few things. First and foremost, a Linux
system. Containers are mostly an abstraction over a root filesystem and
Linux namespaces. We won't go into the specifics of namespaces here, but
if you're curious, the manual page for `namespaces(7)`[^1] contains a nice
overview of the existing namespace types, with links to more detailed
explanations for each type.

As previously mentioned, the other tool we'll need is [bst][bst]. Grab a
release and either build it from source or install the static binaries.

We'll eventually be using BTRFS for our container image management. We don't
really need any specific tool, but installing `btrfs-progs` is typically a
good idea. However, we won't be using BTRFS in this first part -- this will
happen in the next parts.

For our programming language, we'll be using Go. You can pretty much pick
whatever language you fancy, but I'm choosing Go because it's relatively
easy to read and understand unknown Go code, and it's fast to build.

You might be asking yourselves why we're using a third-party utility like
`bst` when we could technically just use Go to setup our namespaces. There
are a few reasons[^2], but the short of it is that Go is good at a lot of
things, but not the particular use-case that led to `bst`. But that's okay
-- we can use Go to build the unprivileged part of our container system,
and it shines way better there.

## First steps: know thy tools

Let's take some time to understand what we can do with bst.  The first visible
side-effect seems to be that bst drops us in a root shell:

{% highlight shell %}
$ id
uid=1000(snaipe) gid=1000(snaipe) groups=1000(snaipe),998(wheel)
$ bst
bst: not enough IDs allocated for snaipe in /etc/subuid (currently 1 allocated). Things may not work as expected, please allocate at least 65534 IDs for it.
bst: not enough IDs allocated for snaipe in /etc/subgid (currently 1 allocated). Things may not work as expected, please allocate at least 65534 IDs for it.
# id
uid=0(root) gid=0(root) groups=0(root),65534(nobody)
{% endhighlight %}

This is not the host root user -- by virtue of user namespaces, this is our
user ID being mapped as the root user. To demonstrate:

{% highlight shell %}
$ echo Bonjour > greeting
$ ls -l
total 4
-rw-r--r-- 1 snaipe snaipe 8 18 oct.  09:49 greeting
$ bst ls -l
bst: not enough IDs allocated for snaipe in /etc/subuid (currently 1 allocated). Things may not work as expected, please allocate at least 65534 IDs for it.
bst: not enough IDs allocated for snaipe in /etc/subgid (currently 1 allocated). Things may not work as expected, please allocate at least 65534 IDs for it.
total 4
-rw-r--r-- 1 root root 8 18 oct.  09:49 greeting
{% endhighlight %}

You might have noticed the two blaring warnings about not having enough IDs to map.
This happens because our real UID and GID do not have any associated sub[ug]id.
Let's allocate ourselves 100000 of them, and confirm that we have the right
IDs allocated:

{% highlight shell %}
$ echo "$USER:1000000:1100000" | sudo tee -a /etc/sub{u,g}id
$ grep $USER -H /etc/sub{u,g}id
/etc/subuid:snaipe:1000000:1100000
/etc/subgid:snaipe:1000000:1100000
$ bst cat /proc/self/uid_map
         0       1000          1
         1    1000000    1100000
$ bst cat /proc/self/gid_map
         0       1000          1
         1    1000000    1100000
{% endhighlight %}

We can indeed see that our current UID (1000) is mapped to UID 0, while UIDs
1000000 to 1100000 are mapped starting from UID 1. More information about
these mappings can be found in the manual page for `subuid(5)`[^3] and related
pages[^4][^5].

Being the root user of a user namespace does give us full control over other
namespaces created under it. For instance, bst gives us our own mount namespace,
so we are able to mount certain things (but not everything) unprivileged.

{% highlight shell %}
$ bst
# mount -t tmpfs tmp /tmp
# ls -l /tmpfs
total 0
# mount /dev/sda1 /mnt
mount: /mnt: permission denied.
{% endhighlight %}

We couldn't mount /dev/sda1 onto /mnt because doing so would have security
implications -- if we could, a malicious user could mount and change the host
root filesystem.

You might now be thinking: "OK, that's great and all, but all this gives me is
access to my own rootfs. Can't we use something else?"

We can indeed! Let's try to download an [Alpine Linux minirootfs][alpine], and
extract it somewhere we can use:

{% highlight shell %}
$ curl -LO http://dl-cdn.alpinelinux.org/alpine/v3.12/releases/x86_64/alpine-minirootfs-3.12.0-x86_64.tar.gz
$ mkdir rootfs
$ tar -xf alpine-minirootfs-3.12.0-x86_64.tar.gz -C rootfs
$ ls rootfs
bin  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
{% endhighlight %}

Alpine Linux is a light, minimalist distribution that is fairly popular in the
Docker world, which makes it a great distribution to hack on.

Let's try using our newfangled rootfs:

{% highlight shell %}
$ bst -r rootfs --no-env TERM=$TERM PATH=/bin:/usr/bin:/sbin:/usr/sbin /bin/sh
/ # env
SHLVL=1
TERM=xterm
PATH=/bin:/usr/bin:/sbin:/usr/sbin
PWD=/
/ # ls /bin
arch           dmesg          gzip           makemime       pipe_progress  stat
ash            dnsdomainname  hostname       mkdir          printenv       stty
base64         dumpkmap       ionice         mknod          ps             su
bbconfig       echo           iostat         mktemp         pwd            sync
busybox        ed             ipcalc         more           reformime      tar
cat            egrep          kbd_mode       mount          rev            touch
chgrp          false          kill           mountpoint     rm             true
chmod          fatattr        link           mpstat         rmdir          umount
chown          fdflush        linux32        mv             run-parts      uname
conspy         fgrep          linux64        netstat        sed            usleep
cp             fsync          ln             nice           setpriv        watch
date           getopt         login          pidof          setserial      zcat
dd             grep           ls             ping           sh
df             gunzip         lzop           ping6          sleep
{% endhighlight %}

Looks good! How about installing some package?

{% highlight shell %}
/ # apk add git
fetch http://dl-cdn.alpinelinux.org/alpine/v3.12/main/x86_64/APKINDEX.tar.gz
ERROR: http://dl-cdn.alpinelinux.org/alpine/v3.12/main: temporary error (try again later)
WARNING: Ignoring APKINDEX.2c4ac24e.tar.gz: No such file or directory
fetch http://dl-cdn.alpinelinux.org/alpine/v3.12/community/x86_64/APKINDEX.tar.gz
ERROR: http://dl-cdn.alpinelinux.org/alpine/v3.12/community: temporary error (try again later)
WARNING: Ignoring APKINDEX.40a3604f.tar.gz: No such file or directory
ERROR: unsatisfiable constraints:
  git (missing):
    required by: world[git]
{% endhighlight %}

Uh oh. It turns out that we haven't configured any network access whatsoever,
so we can't install anything. Let's exit the shell and pass some more flags to
bst:

{% highlight shell %}
$ touch rootfs/etc/resolv.conf
$ bst -r rootfs \
    --share net \
    --mount source=/etc/resolv.conf,target=/etc/resolv.conf,type=none,bind \
    --mount source=proc,target=/proc,type=proc \
    --mount source=dev,target=/dev,type=devtmpfs,mode=755 \
    --mount source=tmp,target=/tmp,type=tmpfs \
    --mount source=run,target=/run,type=tmpfs,mode=755 \
    --no-env \
    TERM=$TERM PATH=/bin:/usr/bin:/sbin:/usr/sbin /bin/sh
{% endhighlight %}

This does a few things:

First, we add some very lazy networking support -- actually bridging the
inner network namespace to the outside is non-trivial and out of scope for
this article. We do this by sharing the network namespace with the host,
and bind-mounting the host /etc/resolv.conf to the inner /etc/resolv.conf
to get DNS to work.

Second, we add default mounts for /proc, /dev, /tmp, and /run. A lot of
programs expect these mounts to be present, so we oblige.

With the new shell, sure enough:

{% highlight shell %}
/ # ping google.com
PING google.com (74.125.193.100): 56 data bytes
64 bytes from 74.125.193.100: seq=0 ttl=42 time=39.268 ms
64 bytes from 74.125.193.100: seq=1 ttl=42 time=40.530 ms
64 bytes from 74.125.193.100: seq=2 ttl=42 time=39.011 ms
^C
--- google.com ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 39.011/39.603/40.530 ms
/ # apk add git
fetch http://dl-cdn.alpinelinux.org/alpine/v3.12/main/x86_64/APKINDEX.tar.gz
fetch http://dl-cdn.alpinelinux.org/alpine/v3.12/community/x86_64/APKINDEX.tar.gz
(1/6) Installing ca-certificates (20191127-r4)
(2/6) Installing nghttp2-libs (1.41.0-r0)
(3/6) Installing libcurl (7.69.1-r1)
(4/6) Installing expat (2.2.9-r1)
(5/6) Installing pcre2 (10.35-r0)
(6/6) Installing git (2.26.2-r0)
Executing busybox-1.31.1-r16.trigger
Executing ca-certificates-20191127-r4.trigger
OK: 22 MiB in 20 packages
{% endhighlight %}

Victory!

At this point, we should have a pretty good idea on how to use bst. It's high
time we started to build the framework of our container system -- our bst
command-line was starting to get pretty big and cumbersome to type.

## Writing the PoC

Let's start writing some Go. The first few things we need to do are writing
the data types describing our containers, and a simple CLI to start a container.

What does a container need? If you think about it, a container has pretty much
the following properties:

* A name
* A root filesystem
* A startup program
* System resource definitions (mounts, interfaces, ...)

For now, let's go with the following data types:

{% highlight go linenos %}
// container.go
package main

// Container represents the properties of a container.
type Container struct {

	// Name is the name of this container.
	Name string

	// Root is the path to the root filesystem of this container.
	Root string

	// Argv is the argv array of the command executed by this container.
	Argv []string

	// Mounts is the list of mounts to perform at the container startup.
	Mounts []MountEntry
}

// MountEntry represents a container mount operation.
type MountEntry struct {

	// Source is the mount source. If a path is specified, it is interpreted
	// relative to the host filesystem.
	Source string

	// Target is the mount target path. It is always interpreted relative to the
	// container root filesystem.
	Target string

	// Type is the mount type. Defaults to "none".
	Type string

	// Options is the list of mount options.
	Options []string
}
{% endhighlight %}

This should get us pretty far. Let's write a function that goes from a Container
to a runnable exec.Cmd:

{% highlight go linenos %}
import (
	"fmt"
	"os/exec"
	"strings"
)

...

func (c *Container) Command() (*exec.Cmd, error) {

	args := []string{
		"-r", c.Root,
	}

	for _, mount := range c.Mounts {
		if mount.Target == "" {
			return nil, fmt.Errorf("Mount entry must have a non-empty target")
		}
		if mount.Source == "" {
			mount.Source = "none"
		}
		if mount.Type == "" {
			mount.Type = "none"
		}
		mountArg := fmt.Sprintf("source=%s,target=%s,type=%s,%s", 
			mount.Source,
			mount.Target,
			mount.Type,
			strings.Join(mount.Options, ","))
		args = append(args, "--mount", mountArg)
	}

	args = append(args, "--workdir", "/", "--")
	args = append(args, c.Command...)

	return exec.Command("bst", args...), nil
}
{% endhighlight %}

With this in hand, let's use it in a dumb main function to see if we can
re-enter our alpine rootfs:

{% highlight go linenos %}
// main.go
package main

import (
	"fmt"
	"os"
)

func fatalf(exit int, msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s: ", os.Args[0])
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(exit)
}

func main() {

	ctnr := Container{
		Name: "alpine",
		Root: "./rootfs",
		Mounts: []MountEntry{
			{
				Source: "proc",
				Target: "/proc",
				Type: "proc",
			},
			{
				Source: "dev",
				Target: "/dev",
				Type: "devtmpfs",
				Options: []string{
					"mode=755",
				},
			},
			{
				Source: "run",
				Target: "/run",
				Type: "tmpfs",
				Options: []string{
					"mode=755",
				},
			},
			{
				Source: "tmp",
				Target: "/tmp",
				Type: "tmpfs",
			},
		},
		Argv: os.Args[1:],
	}

	cmd, err := ctnr.Command()
	if err != nil {
		fatalf(1, "%v", err)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{
		"TERM=" + os.Getenv("TERM"),
		"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
	}

	if err := cmd.Run(); err != nil {
		fatalf(1, "%v", err)
	}
}
{% endhighlight %}

After building this with `go build -o poc .`, Lo and Behold:

{% highlight shell %}
$ ./poc cat /etc/os-release
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.12.0
PRETTY_NAME="Alpine Linux v3.12"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"
{% endhighlight %}

## Persisting the container

Now that we have a PoC, we have to formulate a way to persist information about
the container, as well as its current runtime state. After all, we'd want to
discover running containers and possibly execute new programs in them, and right now,
we not only have no way to do this, but we also lose our containers altogether when
the program exits.

The first straightforward thing to do is to marshal the Container object
somewhere. We can json-encode and store it under a directory that the user
controls, for instance `$XDG_STATE_HOME`[^6]. This is also a good
place to store the container rootfs.

Let's setup by hand our alpine container:

{% highlight shell %}
$ mkdir -p ${XDG_STATE_HOME:-$HOME/.local/state}/toyc/containers/alpine
$ dir=$_
$ mv rootfs "$dir"
$ cat <<'EOF' > "$dir"/container.json
{
	"name": "alpine",
	"root": "rootfs",
	"mounts": [
		{
			"source": "proc",
			"target": "/proc",
			"type": "proc"
		},
		{
			"source": "dev",
			"target": "/dev",
			"type": "devtmpfs",
			"options": ["mode=755"]
		},
		{
			"source": "run",
			"target": "/run",
			"type": "tmpfs",
			"options": ["mode=755"]
		},
		{
			"source": "tmp",
			"target": "/tmp",
			"type": "tmpfs"
		}
	]
}
EOF
$ ls "$dir"
container.json rootfs
{% endhighlight %}

Let's think about what we would like our CLI to look like. We need a command
to create the above container metadata and setup the rootfs, and we need one
to execute a command on it, one to kill a container, one to remove it
entirely, and one to list all of them.

```
$ toyc create <archive> <name>
$ toyc exec <name> <args...>
$ toyc kill <name>
$ toyc rm <name>
$ toyc ps
```

We won't be implementing all of them in this part alone, but this should give
us a good idea of where we want to go.

We can define the commandline boilerplate with something like [Cobra](https://github.com/spf13/cobra):

{% highlight go linenos %}
// main.go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func fatalf(exit int, msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s: ", os.Args[0])
	fmt.Fprintf(os.Stderr, msg, args...)
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(exit)
}

var root = &cobra.Command{
	Use:   "toyc <command>",
	Short: "toyc is a fast, lightweight toy container system.",
}

func main() {
	if err := root.Execute(); err != nil {
		fatalf(2, "%v", err)
	}
}
{% endhighlight %}

Since we just hand-crafted a container, we can start by porting the PoC to the `exec` subcommand:

{% highlight go linenos %}
// exec.go
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

func init() {
	cmd := cobra.Command{
		Use:   "exec [options] [--] <name> <program> [args...]",
		Short: "execute a program in the named container.",
		Run:   execCmd,
		Args:  cobra.MinimumNArgs(2),
	}
	root.AddCommand(&cmd)
}

func execCmd(_ *cobra.Command, args []string) {

	var (
		name = args[0]
		argv = args[1:]
	)

	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" {
		home := os.Getenv("HOME")
		if home == "" {
			fatalf(1, "no state home configured -- set the XDG_STATE_HOME " +
					"or HOME environment variable.")
		}
		stateHome = filepath.Join(home, ".local", "state")
	}

	path := filepath.Join(stateHome, "toyc", "containers", name, "container.json")

	ctnr, err := LoadContainerConfig(path) // Not implemented yet
	if err != nil {
		fatalf(1, "exec %s %s: loading container: %v", name, strings.Join(argv, " "), err)
	}
	ctnr.Argv = argv

	cmd, err := ctnr.Command()
	if err != nil {
		fatalf(1, "exec %s %s: preparing command: %v", name, strings.Join(argv, " "), err)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{
		"TERM=" + os.Getenv("TERM"),
		"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
	}

	if err := cmd.Run(); err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			// Propagate a sensible exit status
			status := err.Sys().(syscall.WaitStatus)
			switch {
			case status.Exited():
				os.Exit(status.ExitStatus())
			case status.Signaled():
				os.Exit(128 + int(status.Signal()))
			}
		}
		fatalf(1, "exec %s %s: running command: %v", name, strings.Join(argv, " "), err)
	}
}
{% endhighlight %}

`toyc exec` is fairly simple: first, construct the real path behind
`${XDG_STATE_HOME:-$HOME/.local/state}/toyc/containers/<name>`, then load that
config from that path into a viable Container object, before finally using the
same logic as the PoC to execute a command in that container.

We just need to implement LoadContainerConfig:

{% highlight go linenos %}
// container.go

...

var (
	ErrContainerNotExist = errors.New("container does not exist")
)

...

// LoadContainerConfig loads a Container from the specified path.
func LoadContainerConfig(path string) (Container, error) {
	f, err := os.Open(filepath.Join(path, "container.json"))
	if os.IsNotExist(err) {
		return Container{}, ErrContainerNotExist
	}
	if err != nil {
		return Container{}, err
	}
	defer f.Close()

	var ctnr Container
	err = json.NewDecoder(f).Decode(&ctnr)

	// Resolve the container root relative to the container directory.
	if !filepath.IsAbs(ctnr.Root) {
		ctnr.Root = filepath.Join(path, ctnr.Root)
	}
	return ctnr, err
}
{% endhighlight %}

LoadContainerConfig is mostly an open-read-decode boilerplate function, but
adds clearer error messaging when the container does not exist. It also resolves
the rootfs path relative to the container directory.

Let's see if that works!

{% highlight shell %}
$ go build -o toyc .
$ ./toyc exec alpine sh -c '. /etc/os-release; echo "Hello from $NAME!"'
Error: unknown shorthand flag: 'c' in -c
Usage:
  toyc exec [options] [--] <name> <program> [args...] [flags]

Flags:
  -h, --help   help for exec
{% endhighlight %}

Oh. Of course, `-c` gets interpreted as a flag for `toyc exec`. Let's tell
cobra to stop processing command-line arguments when it encounters the first
non-flag argument.

{% highlight go linenos %}
// exec.go

...

func init() {
	cmd := cobra.Command{
		Use:   "exec [options] [--] <name> <program> [args...]",
		Short: "execute a program in the named container.",
		Run:   execCmd,
		Args:  cobra.MinimumNArgs(2),
	}
	// Disable flag parsing after the first non-flag argument. This allows us
	// to type commands like `toyc exec ls -l` instead of `toyc exec -- ls -l`.
	cmd.Flags().SetInterspersed(false)
	root.AddCommand(&cmd)
}
{% endhighlight %}

Let's try this again:

{% highlight shell %}
$ go build -o toyc .
$ ./toyc exec alpine sh -c '. /etc/os-release; echo "Hello from $NAME!"'
Hello from Alpine Linux!
{% endhighlight %}

Nice. Our hand-prepared container config got loaded and used to run our little
greeting.

We're pretty much done, right? We can execute commands for a container, and
they all live within the same context, right?

Not so fast:

{% highlight shell %}
$ ./toyc exec alpine sleep infinity &
$ ./toyc exec alpine ps
PID   USER     TIME  COMMAND
    1 root      0:00 bst-init ps
    2 root      0:00 ps
$ fg
^C
{% endhighlight %}

Where did `sleep infinity` go? Well, as far at the current logic is
involved, bst creates a new set of namespaces for every invocation of toyc.
We need to have any subsequent `toyc exec` somehow join the same namespaces as
the first one.

Fortunately, bst has our back once again:

{% highlight shell %}
$ mkdir ns
$ bst --mount tmp,/tmp,tmpfs --persist ./ns sh -c 'touch /tmp/greeting; sleep infinity' &
$ bst --share ./ns sh -xc 'ls /tmp; ps'
+ ls /tmp
greeting
+ ps
    PID TTY          TIME CMD
      1 pts/3    00:00:00 bst-init
      2 pts/3    00:00:00 sleep
      6 pts/3    00:00:00 ps
{% endhighlight %}

In this example, we asked bst to persist the namespaces of the first invocation
into `./ns`, and in the second invocation we ask it to share these namespaces
before running the commands. The end result shows that we've joined the mount
and pid namespaces of the first command, as we can see the contents of the
tmpfs and the `sleep` process.

The `./ns` directory contains for each namespace one associated nsfs file:

{% highlight shell %}
$ ls -l ns
total 0
-r--r--r-- 1 root root 0 18 oct.  20:19 cgroup
-r--r--r-- 1 root root 0 18 oct.  20:19 ipc
-r--r--r-- 1 root root 0 18 oct.  20:19 mnt
-r--r--r-- 1 root root 0 18 oct.  20:19 net
-r--r--r-- 1 root root 0 18 oct.  20:19 pid
-r--r--r-- 1 root root 0 18 oct.  20:19 user
-r--r--r-- 1 root root 0 18 oct.  20:19 uts
{% endhighlight %}

The way this work is that a namespace cannot be freed while there is at most one
active reference to it. Processes that joined a namespace count towards that
reference count, but another way to do it is by bind-mounting the relevant
`/proc/pid/ns/<ns>` file onto any destination, which will keep the namespace
alive while the mount is present. We can, in fact, check this:

{% highlight shell %}
$ grep ns/ /proc/self/mountinfo
735 124 0:4 cgroup:[4026533320] /tmp/ns/cgroup rw - nsfs nsfs rw
736 124 0:4 ipc:[4026533318] /tmp/ns/ipc rw - nsfs nsfs rw
737 124 0:4 mnt:[4026533317] /tmp/ns/mnt rw - nsfs nsfs rw
738 124 0:4 net:[4026533260] /tmp/ns/net rw - nsfs nsfs rw
739 124 0:4 pid:[4026533319] /tmp/ns/pid rw - nsfs nsfs rw
740 124 0:4 user:[4026533258] /tmp/ns/user rw - nsfs nsfs rw
741 124 0:4 uts:[4026533321] /tmp/ns/uts rw - nsfs nsfs rw
{% endhighlight %}

Once done, we can kill the bst we've put in the background and unpersist the
namespace files:

{% highlight shell %}
$ fg
^C
$ bst-unpersist ./ns && rmdir ./ns
{% endhighlight %}

Using this feature, we can change the exec logic of our containers so that
the container incorporates a runtime directory. If that directory does not
exist, we create it and persist the namespaces in it. Conversly, if it exists,
we enter the namespace files in the runtime directory.

{% highlight diff %}
diff --git a/container.go b/container.go
index a0d2610..e835e8a 100644
--- a/container.go
+++ b/container.go
@@ -28,14 +28,25 @@ type Container struct {
 
        // Mounts is the list of mounts to perform at the container startup.
        Mounts []MountEntry
+
+       // RuntimePath is the path to the currently running container.
+       RuntimePath string
 }
 
-func (c *Container) Command() (*exec.Cmd, error) {
+func (c *Container) Command(init bool) (*exec.Cmd, error) {
 
        args := []string{
                "-r", c.Root,
        }
 
+       // Init determines whether or not we are the init process of this
+       // container. The init process always gets started with --persist.
+       if init {
+               args = append(args, "--persist", c.RuntimePath)
+       } else {
+               args = append(args, "--share", c.RuntimePath)
+       }
+
        for _, mount := range c.Mounts {
                if mount.Target == "" {
                        return nil, fmt.Errorf("Mount entry must have a non-empty target")
@@ -77,6 +88,9 @@ func LoadContainerConfig(path string) (Container, error) {
        if !filepath.IsAbs(ctnr.Root) {
                ctnr.Root = filepath.Join(path, ctnr.Root)
        }
+       if !filepath.IsAbs(ctnr.RuntimePath) {
+               ctnr.RuntimePath = filepath.Join(path, ctnr.RuntimePath)
+       }
        return ctnr, err
 }
 
diff --git a/exec.go b/exec.go
index e893dfd..fcd13a1 100644
--- a/exec.go
+++ b/exec.go
@@ -47,7 +47,19 @@ func execCmd(_ *cobra.Command, args []string) {
        }
        ctnr.Argv = argv
 
-       cmd, err := ctnr.Command()
+       // If the runtime path does not exist, we are the first process to start
+       // the container, and its init process.
+       init := false
+       if _, err := os.Stat(ctnr.RuntimePath); os.IsNotExist(err) {
+               if err := os.MkdirAll(ctnr.RuntimePath, 0777); err != nil {
+                       fatalf(1, "exec %s: %v", name, err)
+               }
+               init = true
+       } else if err != nil {
+               fatalf(1, "exec %s: %v", name, err)
+       }
+
+       cmd, err := ctnr.Command(init)
        if err != nil {
                fatalf(1, "exec %s %s: preparing command: %v", name, strings.Join(argv, " "), err)
        }
{% endhighlight %}

Let's change slightly our container.json for alpine:

{% highlight diff %}
index 1bf024d..7a4834b 100644
--- a/home/snaipe/.local/state/toyc/containers/alpine/container.json
+++ b/home/snaipe/.local/state/toyc/containers/alpine/container.json
@@ -1,6 +1,7 @@
 {
 	"name": "alpine",
 	"root": "rootfs",
+	"runtimepath": "ns",
 	"mounts": [
 		{
 			"source": "proc",
{% endhighlight %}

That seems good, let's try it:

{% highlight shell %}
$ go build -o toyc .
$ ./toyc exec alpine echo hello
hello
$ ./toyc exec alpine sh
bst: fork: Out of memory (is the target PID namespace dead?)
{% endhighlight %}

Ah. It turns out that if the init of a PID namespace dies, the PID namespace
becomes defunct and cannot be used anymore. Let's try keeping init alive this
time:

{% highlight shell %}
$ bst-unpersist ${XDG_STATE_HOME:-$HOME/.local/state}/toyc/containers/alpine/ns
$ rmdir $_
$ ./toyc exec alpine sleep infinity &
$ ./toyc exec alpine ps
bst: attempted to mount things in an existing mount namespace.
{% endhighlight %}

Right, there are certain things that we don't want to perform again (like mounts)
when entering an existing container. Fixing the Command function once more:

{% highlight go linenos %}
func (c *Container) Command(init bool) (*exec.Cmd, error) {

	var args []string

	// Init determines whether or not we are the init process of this
	// container. The init process always gets started with --persist.
	if init {
		args = append(args,
			"-r", c.Root,
			"--persist", c.RuntimePath)

		for _, mount := range c.Mounts {
			if mount.Target == "" {
				return nil, fmt.Errorf("Mount entry must have a non-empty target")
			}
			if mount.Source == "" {
				mount.Source = "none"
			}
			if mount.Type == "" {
				mount.Type = "none"
			}
			mountArg := fmt.Sprintf("source=%s,target=%s,type=%s,%s",
				mount.Source,
				mount.Target,
				mount.Type,
				strings.Join(mount.Options, ","))
			args = append(args, "--mount", mountArg)
		}
	} else {
		args = append(args, "--share", c.RuntimePath)
	}

	args = append(args, "--workdir", "/", "--")
	args = append(args, c.Argv...)

	return exec.Command("bst", args...), nil
}
{% endhighlight %}

Let's rebuild and test it once again:

{% highlight shell %}
$ go build -o toyc .
$ ./toyc exec alpine ps
PID   USER     TIME  COMMAND
    1 root      0:00 bst-init sleep infinity
    2 root      0:00 sleep infinity
    7 root      0:00 ps
{% endhighlight %}

Okay, things seem to be working, but we still have the dead namespace problem.
The issue is that there's just no way to recover from a dead PID namespace.
Even if we tried to unshare a new PID namespace while keeping the persisted
other namespaces, we would still end up in a bad state -- for instance, we
would have a mounted /proc that reflects the processes in the defunct PID
namespace, which isn't great.

Since the namespaces are pretty much in a bad state after init exits, we can
take this as hint that we should just call bst-unpersist on the runtime
directory after init exits, and let subsequent execs re-start the container.

{% highlight diff %}
diff --git a/exec.go b/exec.go
index fcd13a1..be02863 100644
--- a/exec.go
+++ b/exec.go
@@ -63,6 +63,21 @@ func execCmd(_ *cobra.Command, args []string) {
        if err != nil {
                fatalf(1, "exec %s %s: preparing command: %v", name, strings.Join(argv, " "), err)
        }
+       if init {
+               // If we are init, the pid namespace dies with us. Cleanup the runtime
+               // directory on exit.
+               defer func() {
+                       unpersist := exec.Command("bst-unpersist", c.RuntimePath)
+                       unpersist.Stdout = os.Stdout
+                       unpersist.Stderr = os.Stderr
+                       if err := unpersist.Run(); err != nil {
+                               fmt.Fprintf(os.Stderr, "cleanup: bst-unpersist %s: %v", c.RuntimePath, err)
+                       }
+                       if err := os.Remove(c.RuntimePath); err != nil {
+                               fmt.Fprintf(os.Stderr, "cleanup: rmdir %s: %v", c.RuntimePath, err)
+                       }
+               }()
+       }
 
        cmd.Stdin = os.Stdin
        cmd.Stdout = os.Stdout
{% endhighlight %}

In theory, this works. In practice, a simple Ctrl-C will not run this defer
function, because the program just SIGINTs. Let's support that through context
cancellation instead:

{% highlight diff %}
diff --git a/container.go b/container.go
index 8b27c10..be2d21d 100644
--- a/container.go
+++ b/container.go
@@ -1,6 +1,7 @@
 package main
 
 import (
+	"context"
 	"errors"
 	"encoding/json"
 	"fmt"
@@ -33,7 +34,7 @@ type Container struct {
 	RuntimePath string
 }
 
-func (c *Container) Command(init bool) (*exec.Cmd, error) {
+func (c *Container) Command(ctx context.Context, init bool) (*exec.Cmd, error) {
 
 	var args []string
 
@@ -68,7 +69,7 @@ func (c *Container) Command(init bool) (*exec.Cmd, error) {
 	args = append(args, "--workdir", "/", "--")
 	args = append(args, c.Argv...)
 
-	return exec.Command("bst", args...), nil
+	return exec.CommandContext(ctx, "bst", args...), nil
 }
 
 // LoadContainerConfig loads a Container from the specified path.
diff --git a/exec.go b/exec.go
index fcd13a1..2b7f3ef 100644
--- a/exec.go
+++ b/exec.go
@@ -1,8 +1,11 @@
 package main
 
 import (
+	"context"
+	"fmt"
 	"os"
 	"os/exec"
+	"os/signal"
 	"path/filepath"
 	"strings"
 	"syscall"
@@ -59,7 +62,16 @@ func execCmd(_ *cobra.Command, args []string) {
 		fatalf(1, "exec %s: %v", name, err)
 	}
 
-	cmd, err := ctnr.Command(init)
+	ctx, cancel := context.WithCancel(context.Background())
+
+	signals := make(chan os.Signal, 1)
+	signal.Notify(signals,
+		syscall.SIGHUP,
+		syscall.SIGINT,
+		syscall.SIGTERM,
+		syscall.SIGQUIT)
+
+	cmd, err := ctnr.Command(ctx, init)
 	if err != nil {
 		fatalf(1, "exec %s %s: preparing command: %v", name, strings.Join(argv, " "), err)
 	}
@@ -72,7 +84,36 @@ func execCmd(_ *cobra.Command, args []string) {
 		"PATH=/bin:/usr/bin:/sbin:/usr/sbin",
 	}
 
-	if err := cmd.Run(); err != nil {
+	done := make(chan error, 1)
+
+	go func() {
+		done <- cmd.Run()
+		close(done)
+	}()
+
+	select {
+	case <-signals:
+		cancel()
+	case err = <-done:
+	}
+	// Make sure the command has been waited for.
+	<-done
+
+	if init {
+		// If we are init, the pid namespace dies with us. Cleanup the runtime
+		// directory on exit.
+		unpersist := exec.Command("bst-unpersist", ctnr.RuntimePath)
+		unpersist.Stdout = os.Stdout
+		unpersist.Stderr = os.Stderr
+		if err := unpersist.Run(); err != nil {
+			fmt.Fprintf(os.Stderr, "cleanup: bst-unpersist %s: %v", ctnr.RuntimePath, err)
+		}
+		if err := os.Remove(ctnr.RuntimePath); err != nil {
+			fmt.Fprintf(os.Stderr, "cleanup: rmdir %s: %v", ctnr.RuntimePath, err)
+		}
+	}
+
+	if err != nil {
 		if err, ok := err.(*exec.ExitError); ok {
 			// Propagate a sensible exit status
 			status := err.Sys().(syscall.WaitStatus)
{% endhighlight %}

We create a cancellable context that we cancel upon hitting a known terminating
signal, then wait for bst to complete. Once done, if this was the init process,
we go ahead and unpersist the runtime directory. This seems to work reasonably
well:

{% highlight shell %}
$ ./toyc exec alpine sh -c 'echo $$'
2
$ ./toyc exec alpine sh -c 'echo $$'
2
{% endhighlight %}

At this point, we are done with our goal for this part. We have a small
container execution system that works. Let's try to benchmark it for
posterity:

{% highlight shell %}
$ perf stat -r 100 -n -- ./toyc exec alpine true

 Performance counter stats for './toyc exec alpine true' (100 runs):

           0,09564 +- 0,00249 seconds time elapsed  ( +-  2,60% )
{% endhighlight %}

That's fast! Here's Docker for a (flawed) comparison:

{% highlight shell %}
$ perf stat -r 100 -n -- docker run --rm -it alpine true

 Performance counter stats for 'docker run --rm -it alpine true' (100 runs):

           1,15534 +- 0,00848 seconds time elapsed  ( +-  0,73% )
{% endhighlight %}

Docker is one order of magnitude slower, but to be fair, it does a lot more
things that our puny toy container system does not do. One of the big features
in particular is image management. We'll see how we can address that while
still trying to be fast in part 2. Stay tuned!

The full code for this series can be found on [GitHub](https://github.com/Snaipe/toy-containers),
and the exact state of the implementation at this point is available under the `part-1` tag.

[^1]: [namespaces(7)](https://www.man7.org/linux/man-pages/man7/namespaces.7.html)

[^2]: If you're interested in the specific reasons:
	
	First, it's not possible to setup user namespaces in pure Go. The creation of
	a user namespace systematically fails with EINVAL if the program is threaded,
	and there is no way to unshare the user namespace before Go creates a thread.
	We could do it via cgo, but it's still bad form, and makes things more complex
	than they should be.
	
	Second, some operations during the setup of namespaces require some special
	privileges, which means that the program has to have some file capabilities set.
	Unfortunately, Go is not very good at safely manipulating capability sets to
	raise our own effective capabilities because of the way Goroutines are scheduled.
	
	Third, Go is still significantly slower than C, which is not where you want to
	be when designing a helper to setup namespacing.

[^3]: [subuid(5)](https://www.man7.org/linux/man-pages/man5/subuid.5.html),
	[subgid(5)](https://www.man7.org/linux/man-pages/man5/subuid.5.html)

[^4]: [newuidmap(1)](https://www.man7.org/linux/man-pages/man1/newuidmap.1.html),
	[newgidmap(1)](https://www.man7.org/linux/man-pages/man1/newgidmap.1.html)

[^5]: [user_namespaces(7)](https://www.man7.org/linux/man-pages/man7/user_namespaces.7.html)

[^6]: note that `$XDG_STATE_HOME` is more of a de-facto standard introduced
	by Debian rather than something actually defined by the XDG base directory
	specification. However, its semantics are exactly the ones we want, as
	`$XDG_CACHE_HOME` represents cache that is safe for the user to blow up,
	and `$XDG_DATA_HOME` represents data files that should be version-controlled.

[alpine]: https://alpinelinux.org/downloads/
[bst]: https://github.com/aristanetworks/bst
