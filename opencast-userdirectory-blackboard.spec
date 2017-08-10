%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define __requires_exclude_from ^.*\\.jar$
%define __provides_exclude_from ^.*\\.jar$

Name:          opencast-userdirectory-blackboard
Summary:       Get roles from Blackboard Learn
Version:       %{version}
Release:       %{buildno}.%{commit}%{?dist}
License:       GPLv3+

Source0:       opencast-userdirectory-blackboard-%{version}.jar
Source1:       org.opencastproject.userdirectory.blackboard-default.cfg.template
URL:           https://git.kis.keele.ac.uk/opencast/opencast-userdirectory-blackboard
BuildRoot:     %{_tmppath}/%{name}-root

BuildArch: noarch


%description
Role provider adding roles from Blackboard Learn to Opencast

%prep


%build


%install
rm -rf %{buildroot}
install -p -d -m 0755 %{buildroot}%{_datadir}/opencast/deploy
install -p -d -m 0755 %{buildroot}%{_sysconfdir}/opencast
install -p -m 644 %{SOURCE0} %{buildroot}%{_datadir}/opencast/deploy/
install -p -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/opencast/

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_datadir}/opencast/deploy/
%config %{_sysconfdir}/opencast/org.opencastproject.userdirectory.blackboard-default.cfg.template


%changelog
* Thu Aug 10 2017 Paul Pettit <p.pettit@keele.ac.uk> - 1.0.0
- Initial build