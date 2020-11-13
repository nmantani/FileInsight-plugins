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
#     powershell -exec bypass -command "& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))) -update"
#     powershell -exec bypass .\install.ps1 -update
#

# Please edit these variables if you use a HTTP proxy server
$PROXY_HOST = "" # example: 10.0.0.1
$PROXY_PORT = "" # example: 8080

if ($PROXY_HOST -and $PROXY_PORT) {
    $PROXY_URL = "http://${PROXY_HOST}:${PROXY_PORT}"
}

$RELEASE_VERSION = "2.4"
$PYTHON_EXE = "C:\Windows\py.exe"
$PYTHON_VERSION = "3.8.6"

# SHA256 Hash values of files that will be downloaded
$FILEINSIGHT_HASH = "005FE63E3942D772F82EC4DF935002AEDB8BBBF10FC95BE086C029A2F3C875A9"
$FILEINSIGHT_PLUGINS_HASH = "2866B7646F9092DA08ACDD06F20AD9FE5FBD185B5CD2A3BC9DC3C56DA903242F"
$PYTHON_HASH = "328A257F189CB500606BB26AB0FBDD298ED0E05D8C36540A322A1744F489A0A0"
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

    # curl.exe has been available since Windows 10 version 1803
    if (Get-Command curl.exe -ea SilentlyContinue) {
        curl.exe -Lo "$save_path" "$url"
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

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\main.py"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] FileInsight-plugins is already installed. Skipping installation."
    } else {
        $old_file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Basic operations\main.py"

        if (Test-Path $old_file_path) {
            Write-Host "[+] Old plugin foler structure has been found. Renaming the 'plugins' folder to 'plugins-old' folder for safekeeping..."
            $from_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins"
            $to_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins-old"
            Move-Item $from_path $to_path

            if (!(Test-Path $to_path)) {
                Write-Host "[!] Rename has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."
        }

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
        $file_path = "$extract_dir\plugins\Operations\XOR\xor_ops.py"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight"
        if (!(Test-Path $dest_dir)) {
            mkdir $dest_dir | Out-Null
        }
        Write-Host "[+] Copying FileInsight-plugins to $dest_dir..."
        Copy-Item "$extract_dir\*" -Destination $dest_dir -Recurse -Force
        if (!(Test-Path "$dest_dir\plugins\Operations\XOR\xor_ops.py")) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."
        Write-Host "[+] FileInsight-plugins $RELEASE_VERSION has been installed."
    }
    Write-Host ""
}

function install_fileinsight($work_dir) {
    Write-Host "[+] Installing FileInsight..."
    $fileinsight_exe = "C:\Program Files (x86)\McAfee\FileInsight\FileInsight.exe"
    if (Test-Path $fileinsight_exe) {
        Write-Host "[*] FileInsight is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading FileInsight installer..."
        $installer_url = "http://downloadcenter.mcafee.com/products/mcafee-avert/fileinsight.msi"
        $installer_msi_path = "$work_dir\fileinsight.msi"
        download_file $installer_url $installer_msi_path

        if (!(Test-Path $installer_msi_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $installer_msi_path (with $FILEINSIGHT_HASH)..."
        $val = compute_hash $installer_msi_path
        if ($val -eq $FILEINSIGHT_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        Write-Host "[+] Executing FileInsight installer (silent installation)..."
        msiexec /i "$installer_msi_path" /passive /norestart ADDLOCAL=ALL | Out-Null
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

function install_python3($work_dir) {
    Write-Host "[+] Installing Python 3 (x64)..."

    if (Test-Path $PYTHON_EXE) {
        Write-Host "[*] Python 3 is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading Python 3 installer..."
        $installer_url = "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-amd64.exe"
        $installer_exe_path = "$work_dir\python-$PYTHON_VERSION-amd64.exe"
        download_file $installer_url $installer_exe_path

        if (!(Test-Path $installer_exe_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $installer_exe_path (with $PYTHON_HASH)..."
        $val = compute_hash $installer_exe_path
        if ($val -eq $PYTHON_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        Write-Host "[+] Executing Python 3 installer (automatic installation)..."
        $process = Start-Process -FilePath "$installer_exe_path" -ArgumentList "/passive" -Verb runas -PassThru
        $process.WaitForExit()

        if (!(Test-Path $PYTHON_EXE)) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        } else {
            Write-Host "[+] Done."
            Write-Host "[+] Installing pip for Python 3..."
            Write-Host "$PYTHON_EXE -3 -m ensurepip"
            Invoke-Expression "$PYTHON_EXE -3 -m ensurepip"
            Write-Host "[+] Done."
            Write-Host "[+] Updating pip for Python 3..."
            Write-Host "$PYTHON_EXE -3 -m pip install --upgrade pip"
            Invoke-Expression "$PYTHON_EXE -3 -m pip install --upgrade pip"
        }
        Write-Host "[+] Done."
        Write-Host "[+] Python 3 has been installed."
    }
    Write-Host ""
}

function install_with_pip($name, $update) {
    Write-Host "[+] Installing $name Python module..."
    $installed = &$PYTHON_EXE -3 -m pip show $name
    if ([bool]$installed -and !$update) {
        Write-Host "[*] $name Python module is already installed. Skipping installation."
    } else {
        if ($update) {
            $upgrade_opt = "--upgrade"
        } else {
            $upgrade_opt = ""
        }

        if ($PROXY_HOST -and $PROXY_PORT) {
            Write-Host "$PYTHON_EXE -3 -m pip install $upgrade_opt $name --proxy ${PROXY_HOST}:${PROXY_PORT}"
            Invoke-Expression "$PYTHON_EXE -3 -m pip install $upgrade_opt $name --proxy ${PROXY_HOST}:${PROXY_PORT}"
        } else {
            Write-Host "$PYTHON_EXE -3 -m pip install $upgrade_opt $name"
            Invoke-Expression "$PYTHON_EXE -3 -m pip install $upgrade_opt $name"
        }
        $installed = &$PYTHON_EXE -3 -m pip show $name
        if ([bool]$installed) {
            Write-Host "[+] Done."
            Write-Host "[+] $name Python module has been installed."
        } else {
            Write-Host "[!] Failed to install $name Python module."
            Write-Host "[!] Please install it manually."
        }
    }
    Write-Host ""
}

function install_python_modules($work_dir, $update) {
    Write-Host "[+] Installing Python modules..."

    install_with_pip "pycryptodomex" $update
    install_with_pip "python-magic-bin" $update
    install_with_pip "pefile" $update
    install_with_pip "capstone" $update
    install_with_pip "qiling" $update
    install_with_pip "watchdog" $update
    install_with_pip "yara-python" $update

    Write-Host "[+] Installing binwalk Python module..."

    $installed = &$PYTHON_EXE -3 -m pip show binwalk
    if ([bool]$installed -and !$update) {
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
        Write-Host "$PYTHON_EXE -3 setup.py install"
        Invoke-Expression "$PYTHON_EXE -3 setup.py install"
        cd $cwd

        $installed = &$PYTHON_EXE -3 -m pip show binwalk
        if (![bool]$installed) {
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

function install_qiling_rootfs($work_dir, $update) {
    Write-Host "[+] Installing rootfs files of Qiling Framework..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x8664_windows\Windows\System32\kernel32.dll"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] rootfs files of Qiling Framework are already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading Qiling Framework..."
        $qiling_url = "https://github.com/qilingframework/qiling/archive/master.zip"
        $zip_archive_path = "$work_dir\qiling-master.zip"
        download_file $qiling_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Extracting qiling-master.zip..."
        $extract_dir = "$work_dir\qiling-master"
        extract_zip $zip_archive_path $work_dir
        $file_path = "$extract_dir\README.md"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc"
        Write-Host "[+] Copying qiling-master to $dest_dir ..."
        Copy-Item $extract_dir -Destination $dest_dir -Recurse -Force
        $file_path = "${dest_dir}\qiling-master\examples\rootfs\x8664_windows\bin\argv.exe"
        if (!(Test-Path $file_path)) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        $cwd = Convert-Path .
        cd "${dest_dir}\qiling-master"
        Write-Host "[+] Setting up DLL files and registry files in ${dest_dir}\qiling-master\examples\rootfs ..."
        Write-Host "[+] Executing ${dest_dir}\qiling-master\examples\scripts\dllscollector.bat ..."
        Start-Process powershell -Verb RunAs -Wait -ArgumentList "-Command `"cd '${dest_dir}\qiling-master'; examples\scripts\dllscollector.bat`""
        $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x8664_windows\Windows\System32\kernel32.dll"
        if (!(Test-Path $file_path)) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        cd $cwd
        Write-Host "[+] Done."
        Write-Host "[+] rootfs files of Qiling Framework have been installed."
    }
    Write-Host ""
}

function install_aplib($work_dir) {
    $version = "1.1.1"
    Write-Host "[+] Installing aPLib..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Compression\aplib.dll"
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

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Compression"
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

function migrate_plugin_config() {
    $old_file_path1 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins-old\Misc operations\send_to.json"
    $old_file_path2 = [Environment]::GetFolderPath('Personal') + "\FileInsight\plugins\Misc operations\send_to.json"
    $new_file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\send_to.json"

    if ((Test-Path $old_file_path1) -and !(Test-Path $new_file_path)) {
        Write-Host "[+] Migrating existing config file from $old_file_path1 to $new_file_path..."
        Copy-Item "$old_file_path1" -Destination "$new_file_path"
        if (!(Test-Path $new_file_path)) {
            Write-Host "[!] Migration failed."
        } else {
            Write-Host "[+] Done."
        }
        Write-Host ""
    } elseif ((Test-Path $old_file_path2) -and !(Test-Path $new_file_path)) {
        Write-Host "[+] Migrating existing config file from $old_file_path2 to $new_file_path..."
        Copy-Item "$old_file_path2" -Destination "$new_file_path"
        if (!(Test-Path $new_file_path)) {
            Write-Host "[!] Migration failed."
        } else {
            Write-Host "[+] Done."
        }
        Write-Host ""
    }
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
    Write-Host "[+] Updating FileInsight-plugins to $RELEASE_VERSION. Existing files will be overwritten."
    install_fileinsight $work_dir
    install_fileinsight_plugins $work_dir $true
    install_python3 $work_dir
    install_python_modules $work_dir $true
    install_qiling_rootfs $work_dir $true
    install_aplib $work_dir
} else {
    install_fileinsight $work_dir
    install_fileinsight_plugins $work_dir $false
    install_python3 $work_dir
    install_python_modules $work_dir
    install_qiling_rootfs $work_dir
    install_aplib $work_dir
}
migrate_plugin_config

remove_working_directory $work_dir
Write-Host "[+] All installation has been finished successfully!"

