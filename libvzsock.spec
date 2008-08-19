%define _incdir /usr/include/vz


Summary: Virtuozzo transport API library
Name: libvzsock
Version: 4.0.0
Release: 1
License: Parallels
Group: System Environment/Libraries
Source: libvzsock.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
Virtuozzo transport API library

#{debug_package}

%prep
rm -rf $RPM_BUILD_ROOT
%setup -n %{name}

%build
make

%install
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%dir %{_libdir}
%attr(755,root,root) %{_libdir}/%{name}.so.*

%package devel
Summary: Virtuozzo transport API development library
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Virtuozzo transport API development library

%files devel
%defattr(-,root,root)
%dir %{_libdir}
%dir %{_incdir}
%attr(755,root,root) %{_libdir}/%{name}.so
%attr(644,root,root) %{_libdir}/%{name}.a
%attr(644,root,root) %{_incdir}/*.h

%changelog
* Tue Aug  5 2008 krasnov@parallels.com  4.0.0-1
- initial packaging
