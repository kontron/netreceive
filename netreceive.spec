Name:       netreceive
Version:    %VERSION%
Release:    %SNAPSHOT%%{?dist}
Summary:    A network bandwidth measurement tool
License:    free
Source:     %SRC_PACKAGE_NAME%.tar.gz
BuildRequires:  glib2-devel jansson-devel libpcap-devel
Requires:       glib2 jansson  libpcap


%description
A network bandwidth measurement tool

%prep
%autosetup -n %SRC_PACKAGE_NAME%

%build

%install
%{make_install}

%files
/usr/sbin/netreceive
/usr/bin/netreceive-plot
