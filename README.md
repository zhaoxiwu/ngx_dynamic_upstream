# ngx_dynamic_upstream

`ngx_dynamic_upstream` is the module for operating upstreams dynamically with HTTP APIs
such as [`ngx_http_upstream_conf`](http://nginx.org/en/docs/http/ngx_http_upstream_conf_module.html).

# Requirements

`ngx_dynamic_upstream` requires the `zone` directive in the `upstream` context.
This directive is available in nginx-1.9.0-plus.

# Status

Production ready.

# Directives

## dynamic_upstream

|Syntax |dynamic_upstream|
|-------|----------------|
|Default|-|
|Context|location|


|Syntax |dynamic_upstream_path|
|-------|----------------|
|Default| /home/work/nginx/conf/vhost/|
|Context|location,server|

Update contents of dynamic_upstream_path/upstream_name.conf, if file not exists nothing will be created

Now `ngx_dynamic_upstream` supports dynamic upstream under only `http` context.

# Quick Start

```nginx
upstream backends {
    zone zone_for_backends 1m;
    server 127.0.0.1:6001;
    server 127.0.0.1:6002;
    server 127.0.0.1:6003;
}

server {
    listen 6000;

    dynamic_upstream_path "/Users/zhaoxiwu/nginx/conf/vhost/";
    location /dynamic {
	allow 127.0.0.1;
	deny all;
        dynamic_upstream;
    }

    location / {
	    proxy_pass http://backends;
    }
}
```

# HTTP APIs

You can operate upstreams dynamically with HTTP APIs.

## list

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends"
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6003;
$
```

## verbose

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends&verbose="
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10;
$
```

## update_parameters

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends&server=127.0.0.1:6003&weight=10&max_fails=5&fail_timeout=5"
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6003 weight=10 max_fails=5 fail_timeout=5;
$
```

The supported parameters are blow.

 * weight
 * max_fails
 * fail_timeout

## down

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends&server=127.0.0.1:6003&down="
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 down;
$
```

## up

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends&server=127.0.0.1:6003&up="
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10;
$
```

## add

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends&add=&server=127.0.0.1:6004"
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6003;
server 127.0.0.1:6004;
$
```

## remove

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends&remove=&server=127.0.0.1:6003"
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6004;
$
```

## Updata content of conf
```bash
 curl "http://127.0.0.1:6000/dynamic?upstream=zone_for_backends&server=127.0.0.1:6003&down="
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 down;


cat conf/vhost/backends.conf
upstream backends{
zone zone_for_backends 1m;
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10;
server 127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 down;
}

```


# License

See [LICENSE](https://github.com/cubicdaiya/ngx_dynamic_upstream/blob/master/LICENSE).
