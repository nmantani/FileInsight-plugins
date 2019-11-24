#
# FileInsight-plugins installation script
#
# Copyright (c) 2019, Nobutaka Mantani
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Usage:
#   Installation:
#     powershell -exec bypass -command "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))"
#     powershell -exec bypass .\install.ps1
#   Update:
#     powershell -exec bypass -command "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1') -update)"
#     powershell -exec bypass .\install.ps1 -update
#

# Please edit these variables if you use a HTTP proxy server
$PROXY_HOST = "" # example: 10.0.0.1
$PROXY_PORT = "" # example: 8080

if ($PROXY_HOST -and $PROXY_PORT) {
    $PROXY_URL = "http://${PROXY_HOST}:${PROXY_PORT}"
}

$RELEASE_VERSION = "1.4.3.1"
$PYTHON_EXE = "C:\Python27\python.exe"
$PYTHON_VERSION = "2.7.17"

# Hash values of files that will be downloaded
$FILEINSIGHT_HASH = "E099B2D0BFB3D2A92F31B2CB5286206E219670FC1D25CD029830832E9CDF4ADD"
$FILEINSIGHT_PLUGINS_HASH = "1AE95445B75AE79DF4ACACE8772D109BC9E2F9BB431CB481F0CB75B252783B75"
$PYTHON_HASH = "A4E3A321517C6B0C2693D6F712A0D18C82600B3D0C759C299B3D14384A17F863"
$APLIB_HASH = "C35C6D3D96CCA8A29FA863EFB22FA2E9E03F5BC2C0293C3256D7AF2E112583B3"

function create_working_directory {
    .{ # Only $temp_dir is used as return value
        if ((Get-Host).Version.Major -ge 5) {
            $temp_dir = New-TemporaryFile
        } else {
            $temp_dir = [System.IO.Path]::GetTempFileName()
        }

        rm $temp_dir
        mkdir $temp_dir

        if (Test-Path $temp_dir) {
            Write-Host "[+] Temporary working directory $temp_dir has been created."
            Write-Host ""
        } else {
            Write-Host "[!] Temporary working directory creation has been failed."
            Write-Host "[+] Aborting installation."
            exit
        }
    } | Out-Null

    return $temp_dir
}

function remove_working_directory($work_dir) {
    Remove-Item $work_dir -Recurse -Force
    Write-Host "[+] Temporary working directory $work_dir has been removed."
}

function download_file($url, $save_path) {
    Write-Host "[+] URL: $url"

    # Check whether .NET Framework supports TLS 1.2 or not
    if ([enum]::GetNames([Net.SecurityProtocolType]) -ccontains "Tls12" `
        -and [Net.ServicePointManager]::SecurityProtocol -cnotcontains "Tls12") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } elseif ([enum]::GetNames([Net.SecurityProtocolType]) -cnotcontains "Tls12") {
        Write-Host "[!] .NET Framework in your environment does not support TLS 1.2 (necessary to download files from GitHub)."
        Write-Host "[!] Please install .NET Framework 4.8 and Windows Management Framework 5.1 that are available from the following locations."
        Write-Host "[!]"
        Write-Host "[!] .NET Framework 4.8"
        Write-Host "[!] https://support.microsoft.com/en-us/help/4503548/microsoft-net-framework-4-8-offline-installer-for-windows"
        Write-Host "[!]"
        Write-Host "[!] Windows Management Framework 5.1"
        Write-Host "[!] https://www.microsoft.com/en-us/download/details.aspx?id=54616"
        Write-Host "[!]"
        return
    }

    if ((Get-Host).Version.Major -ge 3) {
        if ($PROXY_URL) {
            Invoke-WebRequest -Uri $url -OutFile $save_path -Proxy $PROXY_URL
        } else {
            Invoke-WebRequest -Uri $url -OutFile $save_path
        }
    } else {
        Write-Host "[+] Progress of download is not shown. Please be patient."

        $web_client = New-Object System.Net.WebClient

        if ($PROXY_URL) {
            $web_client.Proxy = New-Object System.Net.WebProxy($PROXY_URL, $true)
        }

        $web_client.DownloadFile($url, $save_path)
    }
}

function compute_hash($path) {
    if ((Get-Host).Version.Major -ge 4) {
        $val = (Get-FileHash -Algorithm SHA256 $path).Hash
    } else {
        $val = (certutil -hashfile $path sha256 | select-string "[0-9a-f]{64}" | % { $_.Matches.Value })
    }

    return $val
}

function extract_zip($zip_path, $dest_path) {
    if ((Get-Host).Version.Major -ge 5) {
        Expand-Archive -Path $zip_path -DestinationPath $dest_path
    } else {
        [void] (New-Item -Path $dest_path -ItemType Directory -Force)
        $shell = New-Object -com Shell.Application
        $dest_path = "$dest_path\"
        $shell.Namespace($dest_path).copyhere($shell.NameSpace($zip_path).Items(),4)
    }
}

function install_fileinsight_plugins($work_dir, $update) {
    Write-Host "[+] Installing FileInsight-plugins-$RELEASE_VERSION..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\FileInsight\plugins\Basic operations\main.py"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] FileInsight-plugins is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading FileInsight-plugins-$RELEASE_VERSION..."
        $plugins_url = "https://github.com/nmantani/FileInsight-plugins/archive/v$RELEASE_VERSION.zip"
        $zip_archive_path = "$work_dir\FileInsight-plugins-$RELEASE_VERSION.zip"
        download_file $plugins_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $zip_archive_path (with $FILEINSIGHT_PLUGINS_HASH)..."
        $val = compute_hash $zip_archive_path
        if ($val -eq $FILEINSIGHT_PLUGINS_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        Write-Host "[+] Extracting FileInsight-plugins-$RELEASE_VERSION.zip..."
        $extract_dir = "$work_dir\FileInsight-plugins-$RELEASE_VERSION"
        extract_zip $zip_archive_path $work_dir
        $file_path = "$extract_dir\plugins\XOR operations\main.py"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\FileInsight"
        if (!(Test-Path $dest_dir)) {
            mkdir $dest_dir | Out-Null
        }
        Write-Host "[+] Copying FileInsight-plugins to $dest_dir..."
        Copy-Item "$extract_dir\*" -Destination $dest_dir -Recurse -Force
        if (!(Test-Path "$dest_dir\plugins\XOR operations\main.py")) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."
        Write-Host "[+] FileInsight-plugins has been installed."
    }
    Write-Host ""
}

function install_fileinsight($work_dir) {
    Write-Host "[+] Installing FileInsight..."
    $fileinsight_exe = "C:\Program Files (x86)\FileInsight\FileInsight.exe"
    if (Test-Path $fileinsight_exe) {
        Write-Host "[*] FileInsight is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading FileInsight installer..."
        $installer_url = "http://downloadcenter.mcafee.com/products/mcafee-avert/fileinsight.zip"
        $installer_zip_path = "$work_dir\fileinsight.zip"
        download_file $installer_url $installer_zip_path

        if (!(Test-Path $installer_zip_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $installer_zip_path (with $FILEINSIGHT_HASH)..."
        $val = compute_hash $installer_zip_path
        if ($val -eq $FILEINSIGHT_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        Write-Host "[+] Extracting fileinsight.zip..."
        extract_zip $installer_zip_path $work_dir
        $installer_exe_path = "$work_dir\fileinsight.exe"

        if (!(Test-Path $installer_exe_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Executing FileInsight installer (silent installation)..."
        $process = Start-Process -FilePath "$installer_exe_path" -ArgumentList "/S" -Verb runas -PassThru
        $process.WaitForExit()
        if (!(Test-Path $fileinsight_exe)) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."
        Write-Host "[+] FileInsight has been installed."
    }
    Write-Host ""
}

function install_python2($work_dir) {
    Write-Host "[+] Installing Python 2..."

    if (Test-Path $PYTHON_EXE) {
        Write-Host "[*] Python 2 is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading Python 2 installer..."
        $installer_url = "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION.msi"
        $installer_msi_path = "$work_dir\python-$PYTHON_VERSION.msi"
        download_file $installer_url $installer_msi_path

        if (!(Test-Path $installer_msi_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $installer_msi_path (with $PYTHON_HASH)..."
        $val = compute_hash $installer_msi_path
        if ($val -eq $PYTHON_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        Write-Host "[+] Executing Python 2 installer (automatic installation)..."
        msiexec /i "$work_dir\python-$PYTHON_VERSION.msi" /passive /norestart ADDLOCAL=ALL | Out-Null

        if (!(Test-Path $PYTHON_EXE)) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        } else {
            Write-Host "[+] Done."
            Write-Host "[+] Installing pip for Python 2..."
            Write-Host "$PYTHON_EXE -m ensurepip"
            Invoke-Expression "$PYTHON_EXE -m ensurepip"
        }
        Write-Host "[+] Done."
        Write-Host "[+] Python 2 has been installed."
    }
    Write-Host ""
}

function install_with_pip($name, $file_path) {
    Write-Host "[+] Installing $name Python module..."
    if (Test-Path $file_path) {
        Write-Host "[*] $name Python module is already installed. Skipping installation."
    } else {
        if ($PROXY_HOST -and $PROXY_PORT) {
            Write-Host "$PYTHON_EXE -m pip install $name --proxy ${PROXY_HOST}:${PROXY_PORT}"
            Invoke-Expression "$PYTHON_EXE -m pip install $name --proxy ${PROXY_HOST}:${PROXY_PORT}"
        } else {
            Write-Host "$PYTHON_EXE -m pip install $name"
            Invoke-Expression "$PYTHON_EXE -m pip install $name"
        }
        Write-Host "[+] Done."
        Write-Host "[+] $name Python module has been installed."
    }
    Write-Host ""
}

function install_python_modules($work_dir) {
    Write-Host "[+] Installing Python modules..."

    install_with_pip "pycryptodomex" "C:\Python27\Lib\site-packages\Cryptodome\__init__.py"
    install_with_pip "python-magic-bin" "C:\Python27\Lib\site-packages\magic\__init__.py"
    install_with_pip "pefile" "C:\Python27\Lib\site-packages\pefile.py"
    install_with_pip "yara-python" "C:\Python27\Lib\site-packages\yara.pyd"

    Write-Host "[+] Installing backports.lzma Python module..."
    if (Test-Path "C:\Python27\Lib\site-packages\backports\lzma\__init__.py") {
        Write-Host "[*] backports.lzma Python module is already installed. Skipping installation."
    } else {
        if ($PROXY_HOST -and $PROXY_PORT) {
            Write-Host "$PYTHON_EXE -m pip install -i https://pypi.anaconda.org/nehaljwani/simple backports.lzma --proxy ${PROXY_HOST}:${PROXY_PORT}"
            Invoke-Expression "$PYTHON_EXE -m pip install -i https://pypi.anaconda.org/nehaljwani/simple backports.lzma --proxy ${PROXY_HOST}:${PROXY_PORT}"
        } else {
            Write-Host "$PYTHON_EXE -m pip install -i https://pypi.anaconda.org/nehaljwani/simple backports.lzma"
            Invoke-Expression "$PYTHON_EXE -m pip install -i https://pypi.anaconda.org/nehaljwani/simple backports.lzma"
        }
        Write-Host "[+] Done."
        Write-Host "[+] backports.lzma Python module has been installed."
    }
    Write-Host ""

    Write-Host "[+] Installing binwalk Python module..."
    if (Test-Path "C:\Python27\Lib\site-packages\binwalk\__init__.py") {
        Write-Host "[*] binwalk Python module is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading binwalk..."
        $binwalk_url = "https://github.com/ReFirmLabs/binwalk/archive/master.zip"
        $zip_archive_path = "$work_dir\binwalk-master.zip"
        download_file $binwalk_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Extracting binwalk-master.zip..."
        $extract_dir = "$work_dir\binwalk-master"
        extract_zip $zip_archive_path $work_dir
        $file_path = "$extract_dir\README.md"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $cwd = Convert-Path .
        cd $extract_dir
        Write-Host "$PYTHON_EXE setup.py install"
        Invoke-Expression "$PYTHON_EXE setup.py install"
        cd $cwd

        if (!(Test-Path "C:\Python27\Lib\site-packages\binwalk\__init__.py")) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."
        Write-Host "[+] binwalk Python module has been installed."
    }
    Write-Host ""
}

function install_aplib($work_dir) {
    $version = "1.1.1"
    Write-Host "[+] Installing aPLib..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\FileInsight\plugins\Compression operations\aplib.dll"
    if (Test-Path $file_path) {
        Write-Host "[*] aPLib is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading aPLib-$version..."
        $plugins_url = "http://ibsensoftware.com/files/aPLib-$version.zip"
        $zip_archive_path = "$work_dir\aPLib-$version.zip"
        download_file $plugins_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $zip_archive_path (with $APLIB_HASH)..."
        $val = compute_hash $zip_archive_path
        if ($val -eq $APLIB_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        Write-Host "[+] Extracting aPLib-$version.zip..."
        $extract_dir = "$work_dir\aPLib-$version"
        extract_zip $zip_archive_path $extract_dir
        $file_path = "$extract_dir\lib\dll\aplib.dll"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\FileInsight\plugins\Compression operations"
        Write-Host "[+] Copying aplib.dll to $dest_dir ..."
        Copy-Item $file_path -Destination $dest_dir -Recurse -Force
        if (!(Test-Path "$dest_dir\aplib.dll")) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."
        Write-Host "[+] aPLib has been installed."
    }
    Write-Host ""
}

#
# Main section
#
Write-Host "[+] FileInsight-plugins installation script"
Write-Host ""
if ($PROXY_HOST -and $PROXY_PORT) {
    Write-Host "[+] Using HTTP proxy: $PROXY_URL"
} else {
    Write-Host '[*] NOTE: If you use a HTTP proxy server, please edit $PROXY_HOST and $PROXY_PORT variables in this script.'
}
Write-Host ""
$work_dir = create_working_directory

if ($Args[0] -eq "-update") {
    Write-Host "[+] Updating FileInsight-plugins to $RELEASE_VERSION. Current files will be overwritten."
    install_fileinsight_plugins $work_dir $true
} else {
    install_fileinsight $work_dir
    install_fileinsight_plugins $work_dir $false
    install_python2 $work_dir
    install_python_modules $work_dir
    install_aplib $work_dir
}

remove_working_directory $work_dir
Write-Host "[+] All installation has been finished successfully!"

