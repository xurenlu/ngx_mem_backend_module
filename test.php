<?php
$memcache = new Memcache;
$memcache->connect('localhost', 11211) or die ("Could not connect");
$version = $memcache->getVersion();
echo "Server's version: ".$version."\n";
$data=file_get_contents("./ngx_mem_backend.c");
//$data=$data.$data.$data.$data.$data.$data.$data;
//$data=$data.$data.$data.$data.$data.$data.$data;
$key="/hello/ps2";
$memcache->set($key,$data,false,14400);
print strlen($data);
