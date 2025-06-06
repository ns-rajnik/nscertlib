function is_installed() {
pkgname=$1
if dpkg-query -W -f'${db:Status-Abbrev}\n' $pkgname 2>/dev/null  | grep -q '^.i $'; then
    echo "$pkgname installed"
else
    echo "$pkgname is not installed"
    exit -1
fi
}

is_installed doxygen
is_installed graphviz

doxygen Doxyfile
