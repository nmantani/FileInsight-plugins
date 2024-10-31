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
#     [Executing remote script]
#     powershell -exec bypass -command "IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))"
#     [Executing locally saved script]
#     powershell -exec bypass .\install.ps1
#
#   Update (the latest release version):
#     [Executing remote script]
#     powershell -exec bypass -command "& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))) -update"
#     [Executing locally saved script]
#     powershell -exec bypass .\install.ps1 -update
#
#   Update (the latest snapshot):
#     [Executing remote script]
#     powershell -exec bypass -command "& ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nmantani/FileInsight-plugins/master/install.ps1'))) -update -snapshot"
#     [Executing locally saved script]
#     powershell -exec bypass .\install.ps1 -update -snapshot
#

# This script automatically uses proxy server settings of Windows and you no longer need to manually specify them.
# $PROXY_HOST = "" # example: 10.0.0.1
# $PROXY_PORT = "" # example: 8080

Param(
    [Switch]$update,
    [Switch]$snapshot
)

$RELEASE_VERSION = "2.17.1"
$PYTHON_EMBEDDABLE_PACKAGES_RELEASE_VERSION = "20230527"
$PYTHON_EMBEDDABLE_PACKAGES_SNAPSHOT_VERSION = "20240811"
$APLIB_VERSION = "1.1.1"
$DIE_VERSION = "3.09"
$EXIFTOOL_VERSION = "13.00"
$GIMPHASH_VERSION = "0.2.0"
$LEMMEKNOW_VERSION = "0.8.0"
$QUICKLZ_VERSION = "1.5.0"

$VENV_PATH = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\python3-venv"

# SHA256 Hash values of files that will be downloaded
$FILEINSIGHT_HASH = "005FE63E3942D772F82EC4DF935002AEDB8BBBF10FC95BE086C029A2F3C875A9"
$FILEINSIGHT_PLUGINS_HASH = "64931882134483166F3025E8FF9B4993B174DE95990859A075A4D1F54B415B49"
$PYTHON_EMBEDDABLE_PACKAGES_RELEASE_HASH = "8392f52d4e2bffdc74d6569ab2e214567a333b1156f97fc59193562f0e1a73a3"
$PYTHON_EMBEDDABLE_PACKAGES_SNAPSHOT_HASH = "31A938539D4875016323449A0B2620B3EAEDDC0206BD079FDE18DDFB0EA8AEC6"
$APLIB_HASH = "C35C6D3D96CCA8A29FA863EFB22FA2E9E03F5BC2C0293C3256D7AF2E112583B3"
$DIE_HASH = "299FF9D91CEAD31C32926ECFB5F27D629D06997D259E70AF8632044EDAF27C9B"
$EXIFTOOL_HASH = "BCA1292B39200C15728D4E111B6CA8A8F411BC15D7E0BF1786904CBD240CDDC9"
$GIMPHASH_HASH = "F285B6CB53A5B86182EE506321522A88BCBC029CE37639A39F480D3B0FE1D4CB"
$LEMMEKNOW_HASH = "6983AF87D102BFE6FB00ED67EE64E7968908CB3242F8DEE9E2EB981C297E6C66"
$QUICKLZ_HASH = "C64082498113C220142079B6340BCE3A7B729AD550FCF7D38E08CF8BB2634A28"

function get_proxy_url {
    $settings = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer, ProxyEnable

    if ($settings.ProxyServer -and $settings.ProxyEnable) {
        if ($settings.ProxyServer -ilike "*=*") {
            return ($settings.ProxyServer -replace "=","://" -split(';') | Select-Object -First 1)
        } else {
            return ("http://" + $settings.ProxyServer)
        }
    }
}

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
    $agent = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
    if (Get-Command curl.exe -ea SilentlyContinue) {
        # XXX: setting user-agent header is required to download QuickLZ library
        if ($PROXY_URL) {
            curl.exe -f -x "$PROXY_URL" -A "$agent" -Lo "$save_path" "$url"
        } else {
            curl.exe -f -A "$agent" -Lo "$save_path" "$url"
        }
    } else {
        Write-Host "[+] Progress of download is not shown. Please be patient."

        $web_client = New-Object System.Net.WebClient

        if ($PROXY_URL) {
            $web_client.Proxy = New-Object System.Net.WebProxy($PROXY_URL, $true)
        }

        # XXX: setting user-agent header is required to download QuickLZ library
        $web_client.Headers.Add("user-agent", "$agent")
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
    if (Test-Path "C:\Windows\System32\tar.exe") {
        if (!(Test-Path $dest_path)) {
            mkdir $dest_path | Out-Null
        }
        tar.exe -x -f $zip_path -C $dest_path 2>$null
    } elseif ((Get-Host).Version.Major -ge 5) {
        Expand-Archive -Path $zip_path -DestinationPath $dest_path
    } else {
        [void] (New-Item -Path $dest_path -ItemType Directory -Force)
        $shell = New-Object -com Shell.Application
        $dest_path = "$dest_path\"
        $shell.Namespace($dest_path).copyhere($shell.NameSpace($zip_path).Items(),4)
    }
}

function install_fileinsight_plugins($work_dir, $update, $snapshot) {
    if ($update) {
        if ($snapshot) {
            Write-Host "[+] Updating FileInsight-plugins to the latest snapshot. Existing files will be overwritten."
        } else {
            Write-Host "[+] Updating FileInsight-plugins to $RELEASE_VERSION. Existing files will be overwritten."
        }
    } else {
        if ($snapshot) {
            Write-Host "[+] Installing FileInsight-plugins (the latest snapshot)..."
        } else {
            Write-Host "[+] Installing FileInsight-plugins-$RELEASE_VERSION..."
        }
    }

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

        if ($snapshot) {
            Write-Host "[+] Downloading FileInsight-plugins-master..."
            $plugins_url = "https://github.com/nmantani/FileInsight-plugins/archive/master.zip"
            $zip_archive_path = "$work_dir\FileInsight-plugins-master.zip"
        } else {
            Write-Host "[+] Downloading FileInsight-plugins-$RELEASE_VERSION..."
            #$plugins_url = "https://github.com/nmantani/FileInsight-plugins/archive/v$RELEASE_VERSION.zip" # for testing before release
            $plugins_url = "https://github.com/nmantani/FileInsight-plugins/releases/download/v$RELEASE_VERSION/FileInsight-plugins-$RELEASE_VERSION.zip"
            $zip_archive_path = "$work_dir\FileInsight-plugins-$RELEASE_VERSION.zip"
        }

        download_file $plugins_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        if (!$snapshot) {
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
        }

        if ($snapshot) {
            Write-Host "[+] Extracting FileInsight-plugins-master.zip..."
            $extract_dir = "$work_dir\FileInsight-plugins-master"
            extract_zip $zip_archive_path $work_dir
            $file_path = "$extract_dir\plugins\Operations\XOR\xor_ops.py"
        } else {
            Write-Host "[+] Extracting FileInsight-plugins-$RELEASE_VERSION.zip..."
            $extract_dir = "$work_dir\FileInsight-plugins-$RELEASE_VERSION"
            extract_zip $zip_archive_path $work_dir
            $file_path = "$extract_dir\plugins\Operations\XOR\xor_ops.py"
        }

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

        if ($snapshot) {
            Write-Host "[+] FileInsight-plugins (the latest snapshot) has been installed."
        } else {
            Write-Host "[+] FileInsight-plugins $RELEASE_VERSION has been installed."
        }
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
        #$installer_url = "http://downloadcenter.mcafee.com/products/mcafee-avert/fileinsight.msi"
        $installer_url = "https://downloadcenter.trellix.com/products/mcafee-avert/fileinsight.msi"
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

        Write-Host "[+] Executing FileInsight installer (automatic installation)..."
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

function remove_venv() {
    if ((Test-Path $VENV_PATH)) {
        Write-Host "[+] Removing old Python virtual environment python3-venv..."
        Remove-Item $VENV_PATH -Recurse -Force
        Write-Host "[+] Done."

        if ((Test-Path $VENV_PATH)) {
            Write-Host "[!] Removal of python3-venv has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
    }
}

function install_embeddable_python_packages($work_dir, $update) {
    Write-Host "[+] Installing FileInsight-plugins-embeddable-python-packages..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\python3-embed\python.exe"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] FileInsight-plugins-embeddable-python-packages is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading FileInsight-plugins-embeddable-python-packages $PYTHON_EMBEDDABLE_PACKAGES_VERSION..."
        $archive_url = "https://github.com/nmantani/FileInsight-plugins-embeddable-python-packages/releases/download/$PYTHON_EMBEDDABLE_PACKAGES_VERSION/FileInsight-plugins-python3-embed-$PYTHON_EMBEDDABLE_PACKAGES_VERSION.zip"
        $zip_archive_path = "$work_dir\FileInsight-plugins-python3-embed-$PYTHON_EMBEDDABLE_PACKAGES_VERSION.zip"
        download_file $archive_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $zip_archive_path (with $PYTHON_EMBEDDABLE_PACKAGES_HASH)..."
        $val = compute_hash $zip_archive_path
        if ($val -eq $PYTHON_EMBEDDABLE_PACKAGES_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\python3-embed"

        if ((Test-Path $dest_dir) -and $update) {
            Write-Host "[+] Removing old python3-embed folder..."
            Remove-Item $dest_dir -Recurse -Force
            Write-Host "[+] Done."

            if ((Test-Path $dest_dir)) {
                Write-Host "[!] Removal of old python3-embed folder has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            mkdir $dest_dir | Out-Null
        }

        Write-Host "[+] Extracting FileInsight-plugins-python3-embed-$PYTHON_EMBEDDABLE_PACKAGES_VERSION.zip..."
        $extract_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations"
        extract_zip $zip_archive_path $extract_dir
        $file_path = "$extract_dir\python3-embed\python.exe"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."
        Write-Host "[+] FileInsight-plugins-embeddable-python-packages $PYTHON_EMBEDDABLE_PACKAGES_VERSIONhas been installed."
    }
    remove_venv
    Write-Host ""
}

function install_qiling_rootfs($work_dir, $update) {
    Write-Host "[+] Installing rootfs files of Qiling Framework..."

    $file_path_kernel32_x64 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x8664_windows\Windows\System32\kernel32.dll"
    $file_path_ntoskrnl_x64 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x8664_windows\Windows\System32\ntoskrnl.exe"
    $file_path_kernel32_x86 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x86_windows\Windows\System32\kernel32.dll"
    $file_path_ntoskrnl_x86 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x86_windows\Windows\System32\ntoskrnl.exe"
    $file_path_ntdll_x86 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x86_windows\Windows\System32\ntdll.dll"
    $file_path_libc_x64 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x8664_linux\lib\libc.so.6"
    $file_path_libc_x86 = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs\x86_linux\lib\libc.so.6"

    if ((Test-Path $file_path_kernel32_x64) -and (Test-Path $file_path_ntoskrnl_x64) `
        -and (Test-Path $file_path_kernel32_x86) -and (Test-Path $file_path_ntoskrnl_x86) -and (Test-Path $file_path_ntdll_x86) `
        -and (Test-Path $file_path_libc_x64) -and (Test-Path $file_path_libc_x86) -and !$update) {
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
        $extract_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc"
        extract_zip $zip_archive_path $extract_dir
        $file_path = "$extract_dir\qiling-master\README.md"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Downloading Qiling Framework rootfs..."
        $rootfs_url = "https://github.com/qilingframework/rootfs/archive/master.zip"
        $zip_archive_path = "$work_dir\rootfs-master.zip"
        download_file $rootfs_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples\rootfs"

        if ($update) {
            Write-Host "[+] Removing old rootfs folder..."
            Remove-Item $dest_dir -Recurse -Force
            Write-Host "[+] Done."

            if ((Test-Path $dest_dir)) {
                Write-Host "[!] Removal of old rootfs folder has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            mkdir $dest_dir | Out-Null
        }

        Write-Host "[+] Extracting rootfs-master.zip..."
        $extract_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\qiling-master\examples"
        extract_zip $zip_archive_path $extract_dir
        Move-Item "$extract_dir\rootfs-master\*" "$extract_dir\rootfs"
        Remove-Item "$extract_dir\rootfs-master" -Recurse -Force
        $file_path = "$extract_dir\rootfs\x8664_windows\bin\argv.exe"

        if (!(Test-Path $file_path)) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc"
        $cwd = Convert-Path .
        cd "${dest_dir}\qiling-master"
        Write-Host "[+] Setting up DLL files and registry files in ${dest_dir}\qiling-master\examples\rootfs ..."
        Write-Host "[+] Executing ${dest_dir}\qiling-master\examples\scripts\dllscollector.bat (this requires administrator privileges) ..."
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
    Write-Host "[+] Installing aPLib..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Compression\aplib.dll"
    if (Test-Path $file_path) {
        Write-Host "[*] aPLib is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading aPLib-$APLIB_VERSION..."
        $archive_url = "http://ibsensoftware.com/files/aPLib-$APLIB_VERSION.zip"
        $zip_archive_path = "$work_dir\aPLib-$APLIB_VERSION.zip"
        download_file $archive_url $zip_archive_path

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

        Write-Host "[+] Extracting aPLib-$APLIB_VERSION.zip..."
        $extract_dir = "$work_dir\aPLib-$APLIB_VERSION"
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

function install_detect_it_easy($work_dir, $update) {
    Write-Host "[+] Installing Detect It Easy..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\die_win64_portable\diec.exe"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] Detect It Easy is already installed. Skipping installation."
    } else {
        if ((Test-Path $file_path) -and $update) {
            $current_version = (&$file_path --version).Substring(4)
            $need_install = [System.Version] $current_version -lt $DIE_VERSION
        } else {
            $need_install = $true
        }

        if ($need_install) {
            Write-Host "[+] Downloading Detect It Easy $DIE_VERSION..."
            $archive_url = "https://github.com/horsicq/DIE-engine/releases/download/$DIE_VERSION/die_win64_portable_${DIE_VERSION}_x64.zip"
            $zip_archive_path = "$work_dir\die_win64_portable_$DIE_VERSION.zip"
            download_file $archive_url $zip_archive_path

            if (!(Test-Path $zip_archive_path)) {
                Write-Host "[!] Download has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."

            Write-Host "[+] Verifying SHA256 hash value of $zip_archive_path (with $DIE_HASH)..."
            $val = compute_hash $zip_archive_path
            if ($val -eq $DIE_HASH) {
                Write-Host "[+] OK."
            } else {
                Write-Host "[!] The hash value does not match ($val)."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }

            $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\die_win64_portable"

            if ((Test-Path $dest_dir)) {
                Write-Host "[+] Removing old die_win64_portable folder..."
                Remove-Item $dest_dir -Recurse -Force
                Write-Host "[+] Done."

                if ((Test-Path $dest_dir)) {
                    Write-Host "[!] Removal of old die_win64_portable folder has been failed."
                    remove_working_directory $work_dir
                    Write-Host "[+] Aborting installation."
                    exit
                }
                mkdir $dest_dir | Out-Null
            }

            Write-Host "[+] Extracting die_win64_portable_$DIE_VERSION.zip..."
            $extract_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\die_win64_portable"
            extract_zip $zip_archive_path $extract_dir
            $file_path = "$extract_dir\diec.exe"

            if (!(Test-Path $file_path)) {
                Write-Host "[!] Extraction has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."
            Write-Host "[+] Detect It Easy $DIE_VERSION has been installed."
        } else {
            Write-Host "[*] Detect It Easy $DIE_VERSION is already installed. Skipping installation."
        }
        Write-Host ""
    }
}

function install_exiftool($work_dir, $update) {
    Write-Host "[+] Installing ExifTool..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\exiftool.exe"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] ExifTool is already installed. Skipping installation."
    } else {
        if ((Test-Path $file_path) -and $update) {
            $current_version = &$file_path -ver
            $need_install = [System.Version] $current_version -lt $EXIFTOOL_VERSION
        } else {
            $need_install = $true
        }

        if ($need_install) {
            Write-Host "[+] Downloading ExifTool-$EXIFTOOL_VERSION..."
            $archive_url = "https://exiftool.org/exiftool-${EXIFTOOL_VERSION}_64.zip"
            # Mirror site for website outage
            #$archive_url = "https://jaist.dl.sourceforge.net/project/exiftool/exiftool-${EXIFTOOL_VERSION}_64.zip"
            $zip_archive_path = "$work_dir\exiftool-${EXIFTOOL_VERSION}_64.zip"
            download_file $archive_url $zip_archive_path

            if (!(Test-Path $zip_archive_path)) {
                Write-Host "[!] Download has been failed."
                Write-Host "[*] Please manually download ExifTool from https://exiftool.org/"
                Write-Host "[*] and copy exiftool(-k).exe as '$file_path' ."
                return
            }
            Write-Host "[+] Done."

            Write-Host "[+] Verifying SHA256 hash value of $zip_archive_path (with $EXIFTOOL_HASH)..."
            $val = compute_hash $zip_archive_path
            if ($val -eq $EXIFTOOL_HASH) {
                Write-Host "[+] OK."
            } else {
                Write-Host "[!] The hash value does not match ($val)."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }

            Write-Host "[+] Extracting exiftool-${EXIFTOOL_VERSION}_64.zip..."
            $extract_dir = $work_dir
            extract_zip $zip_archive_path $extract_dir
            $file_path = "$extract_dir\exiftool-${EXIFTOOL_VERSION}_64\exiftool(-k).exe"

            if (!(Test-Path $file_path)) {
                Write-Host "[!] Extraction has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."

            $dest_file = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\exiftool.exe"
            Write-Host "[+] Copying exiftool(-k).exe to $dest_file ..."
            Copy-Item $file_path -Destination $dest_file -Recurse -Force
            if (!(Test-Path "$dest_file")) {
                Write-Host "[!] Installation has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }

            $file_path = "$extract_dir\exiftool-${EXIFTOOL_VERSION}_64\exiftool_files"
            $dest_file = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\exiftool_files"
            Write-Host "[+] Copying exiftool_files to $dest_file ..."
            Copy-Item $file_path -Destination $dest_file -Recurse -Force
            if (!(Test-Path "$dest_file")) {
                Write-Host "[!] Installation has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."
            Write-Host "[+] ExifTool $EXIFTOOL_VERSION has been installed."
        } else {
            Write-Host "[*] ExifTool $EXIFTOOL_VERSION is already installed. Skipping installation."
        }
        Write-Host ""
    }
}

function install_quicklz($work_dir) {
    Write-Host "[+] Installing QuickLZ library..."

    $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Compression"
    if ((Test-Path "$dest_dir\quicklz150_64_1_safe.dll") -and (Test-Path "$dest_dir\quicklz150_64_2_safe.dll") -and (Test-Path "$dest_dir\quicklz150_64_3_safe.dll")) {
        Write-Host "[*] QuickLZ is already installed. Skipping installation."
    } else {
        Write-Host "[+] Downloading QuickLZ-$QUICKLZ_VERSION..."
        $archive_url = "https://web.archive.org/web/20190617194930/http://www.quicklz.com/150dll.zip"
        $zip_archive_path = "$work_dir\150dll.zip"
        download_file $archive_url $zip_archive_path

        if (!(Test-Path $zip_archive_path)) {
            Write-Host "[!] Download has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        Write-Host "[+] Verifying SHA256 hash value of $zip_archive_path (with $QUICKLZ_HASH)..."
        $val = compute_hash $zip_archive_path
        if ($val -eq $QUICKLZ_HASH) {
            Write-Host "[+] OK."
        } else {
            Write-Host "[!] The hash value does not match ($val)."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }

        Write-Host "[+] Extracting 150dll.zip..."
        $extract_dir = "$work_dir\150dll"
        extract_zip $zip_archive_path $extract_dir
        $file_path = "$extract_dir\64\quicklz150_64_1_safe.dll"

        if (!(Test-Path "$extract_dir\64\quicklz150_64_1_safe.dll") -or !(Test-Path "$extract_dir\64\quicklz150_64_2_safe.dll") -or !(Test-Path "$extract_dir\64\quicklz150_64_3_safe.dll")) {
            Write-Host "[!] Extraction has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."

        $dest_dir = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Compression"
        Write-Host "[+] Copying QuickLZ DLL files to $dest_dir ..."
        $file_path = "$extract_dir\64\quicklz150_64_1_safe.dll"
        Copy-Item $file_path -Destination $dest_dir -Recurse -Force
        $file_path = "$extract_dir\64\quicklz150_64_2_safe.dll"
        Copy-Item $file_path -Destination $dest_dir -Recurse -Force
        $file_path = "$extract_dir\64\quicklz150_64_3_safe.dll"
        Copy-Item $file_path -Destination $dest_dir -Recurse -Force
        if (!(Test-Path "$dest_dir\quicklz150_64_1_safe.dll") -or !(Test-Path "$dest_dir\quicklz150_64_2_safe.dll") -or !(Test-Path "$dest_dir\quicklz150_64_3_safe.dll")) {
            Write-Host "[!] Installation has been failed."
            remove_working_directory $work_dir
            Write-Host "[+] Aborting installation."
            exit
        }
        Write-Host "[+] Done."
        Write-Host "[+] QuickLZ library has been installed."
    }
    Write-Host ""
}

function install_gimphash($work_dir, $update) {
    Write-Host "[+] Installing gimphash..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\c_gimphash_windows.exe"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] gimphash is already installed. Skipping installation."
    } else {
            Write-Host "[+] Downloading gimphash $GIMPHASH_VERSION..."
            $download_url = "https://github.com/NextronSystems/gimphash/releases/download/$GIMPHASH_VERSION/c_gimphash_windows.exe"
            $download_file_path = "$work_dir\c_gimphash_windows.exe"
            download_file $download_url $download_file_path

            if (!(Test-Path $download_file_path)) {
                Write-Host "[!] Download has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."

            Write-Host "[+] Verifying SHA256 hash value of $download_file_path (with $GIMPHASH_HASH)..."
            $val = compute_hash $download_file_path
            if ($val -eq $GIMPHASH_HASH) {
                Write-Host "[+] OK."
            } else {
                Write-Host "[!] The hash value does not match ($val)."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }

            $dest_file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Misc\c_gimphash_windows.exe"
            Write-Host "[+] Copying c_gimphash_windows.exe to $dest_file_path ..."
            Copy-Item $download_file_path -Destination $dest_file_path -Force
            if (!(Test-Path "$dest_file_path")) {
                Write-Host "[!] Installation has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."
            Write-Host "[+] gimphash $GIMPHASH_VERSION has been installed."

        Write-Host ""
    }
}

function install_lemmeknow($work_dir, $update) {
    Write-Host "[+] Installing lemmeknow..."

    $file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\lemmeknow-windows.exe"
    if ((Test-Path $file_path) -and !$update) {
        Write-Host "[*] lemmeknow is already installed. Skipping installation."
    } else {
            Write-Host "[+] Downloading lemmeknow $LEMMEKNOW_VERSION..."
            $download_url = "https://github.com/swanandx/lemmeknow/releases/download/v$LEMMEKNOW_VERSION/lemmeknow-windows.exe"
            $download_file_path = "$work_dir\lemmeknow-windows.exe"
            download_file $download_url $download_file_path

            if (!(Test-Path $download_file_path)) {
                Write-Host "[!] Download has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."

            Write-Host "[+] Verifying SHA256 hash value of $download_file_path (with $LEMMEKNOW_HASH)..."
            $val = compute_hash $download_file_path
            if ($val -eq $LEMMEKNOW_HASH) {
                Write-Host "[+] OK."
            } else {
                Write-Host "[!] The hash value does not match ($val)."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }

            $dest_file_path = [Environment]::GetFolderPath('Personal') + "\McAfee FileInsight\plugins\Operations\Parsing\lemmeknow-windows.exe"
            Write-Host "[+] Copying lemmeknow-windows.exe to $dest_file_path ..."
            Copy-Item $download_file_path -Destination $dest_file_path -Force
            if (!(Test-Path "$dest_file_path")) {
                Write-Host "[!] Installation has been failed."
                remove_working_directory $work_dir
                Write-Host "[+] Aborting installation."
                exit
            }
            Write-Host "[+] Done."
            Write-Host "[+] lemmeknow $LEMMEKNOW_VERSION has been installed."

        Write-Host ""
    }
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

$PROXY_URL = get_proxy_url

if ($PROXY_URL) {
    Write-Host "[+] Using HTTP proxy: $PROXY_URL"
    Write-Host ""
}

if ($snapshot) {
    $PYTHON_EMBEDDABLE_PACKAGES_VERSION = $PYTHON_EMBEDDABLE_PACKAGES_SNAPSHOT_VERSION
    $PYTHON_EMBEDDABLE_PACKAGES_HASH = $PYTHON_EMBEDDABLE_PACKAGES_SNAPSHOT_HASH
} else {
    $PYTHON_EMBEDDABLE_PACKAGES_VERSION = $PYTHON_EMBEDDABLE_PACKAGES_RELEASE_VERSION
    $PYTHON_EMBEDDABLE_PACKAGES_HASH = $PYTHON_EMBEDDABLE_PACKAGES_RELEASE_HASH
}

$work_dir = create_working_directory

install_fileinsight $work_dir
install_fileinsight_plugins $work_dir $update $snapshot
install_embeddable_python_packages $work_dir $update
install_detect_it_easy $work_dir $update
install_qiling_rootfs $work_dir $update
install_aplib $work_dir
if (!$snapshot) {
    install_exiftool $work_dir $update
}
install_quicklz $work_dir
install_gimphash $work_dir $update
install_lemmeknow $work_dir $update

migrate_plugin_config

remove_working_directory $work_dir
Write-Host "[+] All installation has been finished!"
