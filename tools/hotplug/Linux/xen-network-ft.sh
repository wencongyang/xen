#
# Copyright (C) 2014 FUJITSU LIMITED
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# ifb is stored in /libxl/<domid>/<path>/<devid>/<file>
PATH_LIST=(
    remus/netbuf
    colo_agent
    colo_agent
)

FILE_LIST=(
    ifb
    ifb_primary
    ifb_secondary
)

# check_one_ifb_file $domid $path $file
function check_one_ifb_file()
{
    local domid=$1
    local path=$2
    local file=$3
    local full_path=
    local ifb=

    for devid in `xenstore-list "/libxl/$domid/$path" 2>/dev/null || true`
    do
        full_path="/libxl/$domid/$path/$devid/$file"
        xenstore-exists $full_path || continue
        ifb=`xenstore-read "$full_path" 2>/dev/null || true`
        [ "$ifb" = "$1" ] && return 1
    done

    return 0
}

# return 0 if the ifb is free
function check_ifb()
{
    local installed=`nl-qdisc-list -d $1`
    local path=
    local file=
    local -i index=0

    [ -n "$installed" ] && return 1

    for domid in `xenstore-list "/local/domain" 2>/dev/null || true`
    do
        [ $domid -eq 0 ] && continue

        index=0
        for path in "${PATH_LIST[@]}"; do
            index=$((index + 1))
            xenstore-exists "/libxl/$domid/$path" || continue
            file=${FILE_LIST[index]}

            check_one_ifb_file $domid $path $file || return 1
        done
    done

    return 0
}

# setup_ifb $nic_name $file_name
# Note:
#   1. The caller should acquire the lock pickifb
#   2. ifb name will be stored in $XENBUS_PATH/$file_name
function setup_ifb()
{
    local nic_name=$1
    local file_name=$2
    local found=0

    for ifb in `ifconfig -a -s|egrep ^ifb|cut -d ' ' -f1`
    do
        check_ifb "$ifb" || continue
        found=1
        break
    done

    if [ $found -eq 0 ]
    then
        fatal "Unable to find a free ifb device for $nic_name"
    fi

    xenstore_write "$XENBUS_PATH/$file_name" "$ifb"
    do_or_die ip link set dev "$ifb" up
}
