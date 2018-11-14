#!/bin/bash -xe

if [ "$1" = "--help" ] ; then
  echo "Usage: <version> <type> <number>"
  return
fi

version="$1"
type="$2"
suffix="$3"
repo="$4"
host="$5"
key="$6"

[ -z $version ] && exit 1
[ -z $type ] && exit 2
[ -z $suffix ] && exit 3

sed -i -E -e 'H;1h;$!d;x' -e "s/libindy-crypto ([(,),0-9,.]+)/libindy-crypto ($version$suffix)/" debian/changelog

dpkg-buildpackage -tc

mkdir debs &&  mv ../*.deb ./debs/

./sovrin-packaging/upload_debs.py ./debs $repo $type --host $host --ssh-key $key
