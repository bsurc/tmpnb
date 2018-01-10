Summary: Temporary Jupyter Notebook Server
Name: tmpnb
Version: 0.1
Release: 1
Group: Development/Tools
License: BSD-3
Source: $GOPATH/src/github.com/bsurc/tmpnb
BuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}

%description
%{summary}

%prep
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/etc/tmpnb/assets
mkdir -p $RPM_BUILD_ROOT/etc/systemd/system
cd $RPM_BUILD_ROOT
cp %{SOURCEURL0}/config.json ./etc/tmpnb.json
cp %{SOURCEURL0}/pkg/systemd/tmpnb.service ./etc/systemd/system/tmpnb.service
cp -r %{SOURCEURL0}/assets/templates $RPM_BUILD_ROOT/etc/tmpnb/assets
cp -r %{SOURCEURL0}/assets/static $RPM_BUILD_ROOT/etc/tmpnb/assets

%build
cd %{SOURCEURL0}
go build

%install
cd $RPM_BUILD_ROOT
cp %{SOURCEURL0}/tmpnb ./usr/bin/tmpnb

%clean
rm -r -f "$RPM_BUILD_ROOT"

%files
%defattr(644,root,root)
%config(noreplace) %{_sysconfdir}/tmpnb.json
%config(noreplace) %{_sysconfdir}/systemd/system/tmpnb.service
%config(noreplace) %{_sysconfdir}/tmpnb/assets/templates/*
%config(noreplace) %{_sysconfdir}/tmpnb/assets/static/*
%defattr(755,root,root)
%{_bindir}/tmpnb
