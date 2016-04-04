#/bin/bash

# Set the GOPATH if it is not set or if is different when running as another user (sudo)
# export GOPATH="" 

PATH_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

PATH_BUILD="$GOPATH/bin/generator-gpu_release"
mkdir -p $PATH_BUILD

# Linux
export GOOS="linux"

export GOARCH="amd64"
echo "Compiling... (OS: $GOOS, ARCH: $GOARCH)"
go build -o "$PATH_BUILD/linux_64"
echo "Done"
echo

export GOARCH="386"
echo "Compiling... (OS: $GOOS, ARCH: $GOARCH)"
go build -o "$PATH_BUILD/linux_32"
echo "Done"
echo

# Windows
export GOOS="windows"

export GOARCH="amd64"
echo "Compiling... (OS: $GOOS, ARCH: $GOARCH)"
go build -o "$PATH_BUILD/win_64"
echo "Done"
echo

export GOARCH="386"
echo "Compiling... (OS: $GOOS, ARCH: $GOARCH)"
go build -o "$PATH_BUILD/win_32"
echo "Done"
echo

# Darwin
export GOOS="darwin"

export GOARCH="amd64"
echo "Compiling... (OS: $GOOS, ARCH: $GOARCH)"
go build -o "$PATH_BUILD/mac_64"
echo "Done"
echo

export GOARCH="386"
echo "Compiling... (OS: $GOOS, ARCH: $GOARCH)"
go build -o "$PATH_BUILD/mac_32"
echo "Done"
echo

# Copy binaries to bin branch
echo "Stashing master branch..."
git stash

echo "Checkout bin branch..."
git checkout bin

echo "Copying compiled binaries..."
cp -af "$PATH_BUILD/linux_64"	"$PATH_SCRIPT/linux_64"
cp -af "$PATH_BUILD/linux_32"	"$PATH_SCRIPT/linux_32"

cp -af "$PATH_BUILD/win_64"		"$PATH_SCRIPT/win_64"
cp -af "$PATH_BUILD/win_32"		"$PATH_SCRIPT/win_32"

cp -af "$PATH_BUILD/mac_64"		"$PATH_SCRIPT/mac_64"
cp -af "$PATH_BUILD/mac_32"		"$PATH_SCRIPT/mac_32"

echo "Done"
echo "Please commit and push binaries and then checkout master branch."
echo "You may also unstach master branch: 'git stash pop'"