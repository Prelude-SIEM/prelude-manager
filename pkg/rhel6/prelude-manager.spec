Name:  prelude-manager
Epoch:  1
Version: 1.0.2
Release: 1%{?dist}
Summary: Prelude-Manager

Group:  Applications/Internet
License: GPLv2+
URL:  http://www.prelude-ids.org
Source0: http://www.prelude-ids.org/download/releases/%{name}/%{name}-%{version}.tar.gz
Source1: %{name}.init
#Patch1:  %{name}-1.0.1-pie.patch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libpreludedb-devel, libxml2-devel
BuildRequires:  libprelude-devel >= 0.9.21.3
%if 0%{?fedora} > 6
BuildRequires:  tcp_wrappers-devel
%else
BuildRequires:  tcp_wrappers
%endif
Requires(pre)   : /usr/sbin/useradd
Requires(post) : /sbin/chkconfig
Requires(preun) : /sbin/chkconfig
Requires(preun) : /sbin/service
Requires(postun): /sbin/service

%description
Prelude-Manager is a high availability server that accepts
secured connections from distributed sensors and/or other Managers
and saves received events to a media specified by the user
(database, log file, mail etc.). The server schedules and
establishes the priorities of treatment according to the
critical character and the source of the alerts.

%package devel
Summary: Header files and libraries for prelude-manager development
Group: Development/Libraries
Requires: prelude-manager = %{epoch}:%{version}-%{release}, libpreludedb-devel

%description devel
Libraries, include files for Prelude-Manager.

%package        db-plugin
Summary: Database report plugin for Prelude IDS Manager
Group:  System Environment/Libraries
Requires: %{name} = %{epoch}:%{version}-%{release}

%description    db-plugin
This plugin allows prelude-manager to write to database.

%package xml-plugin
Summary: XML report plugin for Prelude IDS Manager
Group:  System Environment/Libraries
Requires: %{name} = %{epoch}:%{version}-%{release}

%description    xml-plugin
This plugin adds XML logging capabilities to prelude-manager.

%package smtp-plugin
Summary: SMTP alert plugin for Prelude IDS Manager
Group:  System Environment/Libraries
Requires: %{name} = %{epoch}:%{version}-%{release}

%description    smtp-plugin
This plugin adds alerting by email capabilities to prelude-manager

%prep
%setup -q
#%patch1 -p1

%build
export CFLAGS="$RPM_OPT_FLAGS"
%configure --with-libwrap
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_defaultdocdir}/%{name}-%{version}
mkdir -p %{buildroot}/%{_initrddir}
mkdir -p %{buildroot}/%{_var}/spool/prelude-manager/scheduler
make install DESTDIR=%{buildroot} INSTALL="%{__install} -c -p"
install -m 755 %{SOURCE1} %{buildroot}/%{_initrddir}/%{name}
rm -f %{buildroot}/%{_libdir}/%{name}/reports/*.la
rm -f %{buildroot}/%{_libdir}/%{name}/filters/*.la
rm -f %{buildroot}/%{_libdir}/%{name}/decodes/*.la
rm -f %{buildroot}%{_defaultdocdir}/%{name}/smtp/template.example

%clean
rm -rf %{buildroot}

%pre
getent passwd prelude-manager >/dev/null || \
/usr/sbin/useradd -M -o -r -d / -s /sbin/nologin \
        -c "prelude-manager" -u 61 prelude-manager > /dev/null 2>&1 || :

%post
/sbin/ldconfig
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
 /sbin/service %{name} stop > /dev/null 2>&1 || :
 /sbin/chkconfig --del %{name}
fi

%postun 
/sbin/ldconfig
if [ "$1" -ge "1" ]; then
 /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc COPYING
%attr(0750,root,root) %dir %{_sysconfdir}/%{name}/
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/%{name}/*
%{_initrddir}/%{name}
%dir %{_bindir}/%{name}
%dir %{_libdir}/%{name}/
%dir %{_libdir}/%{name}/filters/
%{_libdir}/%{name}/filters/*.so
%dir %{_libdir}/%{name}/reports/
%{_libdir}/%{name}/reports/debug.so
%{_libdir}/%{name}/reports/textmod.so
%{_libdir}/%{name}/reports/relaying.so
%dir %{_libdir}/%{name}/decodes/
%{_libdir}/%{name}/decodes/*.so
%attr(0750,root,root) %dir %{_localstatedir}/spool/%{name}/
%attr(0750,root,root) %dir %{_localstatedir}/spool/%{name}/scheduler
%attr(0750,root,root) %dir %{_localstatedir}/run/%{name}/
%attr(0750,root,root) %dir %{_datadir}/%{name}/
%attr(0644,root,root) %{_mandir}/man1/prelude-manager.1.gz

%files db-plugin
%defattr(-,root,root,-)
%{_libdir}/%{name}/reports/db.so

%files xml-plugin
%defattr(-,root,root,-)
%{_libdir}/%{name}/reports/xmlmod.so
%attr(0750,root,root) %dir %{_datadir}/%{name}/xmlmod/
%{_datadir}/%{name}/xmlmod/*

%files smtp-plugin
%defattr(-,root,root,-)
%doc %attr(0644,root,root) plugins/reports/smtp/template.example
%{_libdir}/%{name}/reports/smtp.so

%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/%{name}/
%{_includedir}/%{name}/*


%changelog
* Wed Jun 15 2011 Vincent Quéméner <vincent.quemener@c-s.fr> 1.0.1-3
- Rebuilt for RHEL6

* Fri Mar 25 2011 Steve Grubb <sgrubb@redhat.com> 1.0.1-2
- Disable pie patch for now

* Thu Mar 24 2011 Steve Grubb <sgrubb@redhat.com> 1.0.1-1
- new upstream version

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1:1.0.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sun May 02 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0-3
- Fix requires

* Fri Apr 30 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0-2
- new upstream version

* Sat Jan 30 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0rc1-1
- new upstream version

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.15-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Fri Jul 10 2009 Steve Grubb <sgrubb@redhat.com> 0.9.15-1
- new upstream version

* Wed Apr 22 2009 Steve Grubb <sgrubb@redhat.com> 0.9.14.2-3
- Adjusted permissions on dirs and conf files

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.9.14.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Aug 27 2008 Steve Grubb <sgrubb@redhat.com> 0.9.14.2-1
- new upstream version

* Mon Jul 21 2008 Steve Grubb <sgrubb@redhat.com> 0.9.14-1
- new upstream version

* Fri Jun 27 2008 Steve Grubb <sgrubb@redhat.com> 0.9.13-1
- new upstream version 0.9.13
- Prelude-Manager-SMTP plugin is now included

* Tue Jun 24 2008 Steve Grubb <sgrubb@redhat.com> 0.9.12.1-2
- add prelude-manager user

* Fri May 02 2008 Steve Grubb <sgrubb@redhat.com> 0.9.12.1-1
- new upstream version 0.9.12.1

* Thu Apr 24 2008 Steve Grubb <sgrubb@redhat.com> 0.9.12-1
- new upstream version 0.9.12

* Mon Jan 14 2008 Steve Grubb <sgrubb@redhat.com> 0.9.10-1
- new upstream version 0.9.10

* Thu Feb 08 2007 Thorsten Scherf <tscherf@redhat.com> 0.9.7.1-4
- fixed Prelude trac #193

* Sun Jan 07 2007 Thorsten Scherf <tscherf@redhat.com> 0.9.7.1-3
- added tcp-wrapper support
- fixed dirowner and permissions problem

* Fri Jan 05 2007 Thorsten Scherf <tscherf@redhat.com> 0.9.7.1-2
- fixed encoding problems
- changed dirowner
- resolved dependency problems

* Sat Dec 30 2006 Thorsten Scherf <tscherf@redhat.com> 0.9.7.1-1
- moved to new upstream version 0.9.7.1
- changed dirowner

* Mon Nov 20 2006 Thorsten Scherf <tscherf@redhat.com> 0.9.6.1-2
- Some minor fixes in requirements

* Tue Oct 24 2006 Thorsten Scherf <tscherf@redhat.com> 0.9.6.1-1
- New Fedora build based on release 0.9.6.1
