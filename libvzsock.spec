%define _incdir /usr/include/vz
%define _sampledir /usr/share/libvzsock/samples


Summary: @PRODUCT_NAME_LONG@ transport API library
Name: libvzsock
Version: 5.0.0
Release: 2
License: Parallels
Group: System Environment/Libraries
Source: libvzsock.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
@PRODUCT_NAME_LONG@ transport API library

#{debug_package}

%prep
rm -rf $RPM_BUILD_ROOT
%setup -n %{name}

%build
make

%install
make install DESTDIR=$RPM_BUILD_ROOT
# generate test private key and certificate
openssl genrsa > $RPM_BUILD_ROOT/%{_sampledir}/test.key
openssl req -new -key $RPM_BUILD_ROOT/%{_sampledir}/test.key -x509 -days 365 -subj /C=RU/ST=Moscow/L=Moscow/O=Company/OU=LinuxDev/CN=User/ -out $RPM_BUILD_ROOT/%{_sampledir}/test.crt -set_serial 0

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%dir %{_libdir}
%attr(755,root,root) %{_libdir}/%{name}.so.*

%package devel
Summary: @PRODUCT_NAME_LONG@ transport API development library
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
@PRODUCT_NAME_LONG@ transport API development library

%files devel
%defattr(-,root,root)
%dir %{_libdir}
%dir %{_incdir}
%dir %{_sampledir}
%attr(755,root,root) %{_libdir}/%{name}.so
%attr(644,root,root) %{_libdir}/%{name}.a
%attr(644,root,root) %{_incdir}/*.h
%attr(644,root,root) %{_sampledir}/*

%changelog
* Tue Jan 25 2011 krasnov@parallels.com 5.0.0-2
- close unused descriptors in child on ssh open_conn()

* Mon Mar 22 2010 krasnov@parallels.com 4.6.0-2
- IPv6 support for socket was added

* Sat Mar 21 2009 krasnov@parallels.com 4.0.0-3
- _accept() for socket fixed

* Wed Dec 10 2008 krasnov@parallels.com 4.0.0-2
- some functions added
- ##131684,131685,131686 fixed 

* Tue Aug  5 2008 krasnov@parallels.com  4.0.0-1
- initial packaging
