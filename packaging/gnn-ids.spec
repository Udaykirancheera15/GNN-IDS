Name:       gnn-ids
Version:    %{_version}
Release:    %{_release}%{?dist}
Summary:    GNN-based Network Intrusion Detection System
License:    MIT
Source0:    %{name}-%{version}.tar.gz
BuildArch:  x86_64

# DISABLE DEBUG PACKAGE GENERATION (Fixes the eu-strip error)
%define debug_package %{nil}

# DISABLE AUTOMATIC DEPENDENCIES (Fixes the Conda/libgfortran dnf error)
AutoReq: no

Requires:   python3 >= 3.10
Requires:   python3-pip
Requires:   libpcap

%description
A Graph Neural Network (GraphSAGE) based intrusion detection system.
Performs real-time network traffic analysis using a pre-trained ONNX model
exported from a CIC-IDS-2017 trained GraphSAGE architecture.
Runs on CPU via ONNX Runtime — no GPU required in production.

%prep
%setup -q

%install
mkdir -p %{buildroot}
cp -r opt          %{buildroot}/
cp -r usr          %{buildroot}/
cp -r etc          %{buildroot}/
mkdir -p %{buildroot}/var/log/gnn-ids

# Install Python dependencies into the package-local directory
pip3 install --target %{buildroot}/opt/gnn-ids/lib \
    onnxruntime scikit-learn scapy numpy 2>/dev/null || true

%post
# Add lib path to Python search path for the service
echo "/opt/gnn-ids/lib" > /usr/lib/python3/dist-packages/gnn-ids.pth 2>/dev/null || \
echo "/opt/gnn-ids/lib" > /usr/lib/python3.10/site-packages/gnn-ids.pth 2>/dev/null || true
systemctl daemon-reload

%preun
if [ $1 -eq 0 ]; then
    systemctl stop    gnn-ids 2>/dev/null || true
    systemctl disable gnn-ids 2>/dev/null || true
fi

%postun
systemctl daemon-reload

%files
%defattr(-,root,root,-)
/opt/gnn-ids/
/usr/bin/gnn-ids
/usr/lib/systemd/system/gnn-ids.service
%config(noreplace) /etc/gnn-ids/gnn-ids.conf
%dir /var/log/gnn-ids

%changelog
* Sat Feb 21 2026 MLOps Architect <cheeraudaykiran@gmail.com> 1.0.0-1
- Initial production release with GraphSAGE + ONNX Runtime
