Throttle Plugin
===============

This is a very simple connection throttling plugin. It takes a few
parameters:

`max`: This specifies the maximum number of simultaneous uncached
requests that can be served. Any requests that exceed this limit will
either be served stale, if allowed, or return 503 Unavailable.

`stale`: This is how long to serve stale content for, in seconds. If
content has a `stale-on-error` Cache Control header, the greater of
these is honoured instead.

`statfreq`: The interval, in milliseconds, between statistics dumps.
These will be written to the `throttle.log` file.

`id`: The identifier for this remap rule. Statistics are logged with
this id so they can be disambiguated. May not contain spaces.

`file`: This isn't really a parameter. Instead, the contents of the
referenced file will be loaded and parsed for parameters.

Request Handling
----------------

When a request comes in for a throttled remap, if it can be served fresh
from the cache, it is. Otherwise, the request counts against the maximum
defined by `max`.

If the current number of requests in-flight exceeds the quota, then the
request will not be allowed to request content from upstream caches or
origins. If either the `stale` parameter or a `stale-if-error` cache
control header allow the content to be served stale, it will be.
Otherwise, a 503 Unavailable error will be returned to the client.

Statistics
----------

Some basic statistics are logged to `throttle.log` in the log directory.
Each log line looks like this:

    <date> tpid=<id> tph=<high_water_mark> tpu=<unavailable> tps=<stale>

`tpid`: The identifier provided in the `id` parameter for the given
remap.

`tph`: A high water mark that indicates the maximum number of
simultaneous connections during the previous logging interval. This can
be slightly more than `max` on occasion because connections are very
briefly held for serving cached content and rejecting requests.

`tpu`: Total count of 503s returned by the throttle plugin in the
previous logging interval.

`tps`: Total count of requests served stale content by the throttle
plugin in the previous logging interval.

Config Format
-------------

The throttle plugin uses a very loose format for configuration
variables. In general, use `param:value` to specify parameters. For
example, this might serve as a config file:

    id:example-01
    max:2000
    stale:3600
    statfreq:10000

It might be referenced in a remap line like this:

    @plugin=throttle.so @pparam=file:example-01-throttle.config

If necessary, the file argument (only!) accepts backslashes to escape
spaces and backslashes:

    @plugin=throttle.so @pparam=file:example\ 01\ throttle.config
