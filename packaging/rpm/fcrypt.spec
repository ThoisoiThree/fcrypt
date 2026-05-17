%global debug_package %{nil}
%global pkg_version %{?pkg_version}%{!?pkg_version:0.0.0}

Name:           fcrypt
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        Password-based file encryption and decryption CLI

License:        MIT
URL:            https://github.com/ThoisoiThree/fcrypt

%description
fcrypt is a cross-platform command-line utility for password-based file
encryption and decryption. It uses AES-256-GCM authenticated encryption and
Argon2id password-based key derivation.

%prep

%build

%install
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_sourcedir}/fcrypt %{buildroot}%{_bindir}/fcrypt

install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 %{_sourcedir}/README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 %{_sourcedir}/CHANGELOG.md %{buildroot}%{_docdir}/%{name}/CHANGELOG.md

install -d -m 0755 %{buildroot}%{_licensedir}/%{name}
install -m 0644 %{_sourcedir}/LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%{_bindir}/fcrypt
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/CHANGELOG.md
%license %{_licensedir}/%{name}/LICENSE

%changelog
* Sun May 17 2026 ThoisoiThree <noreply@github.com> - %{pkg_version}-1
- Build upstream fcrypt release package.
