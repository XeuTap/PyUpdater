
@ECHO off
chcp 65001
echo Updating to latest version... > %appdata%/extract_info_2.txt
set a=1
set observable_file="C:\TRAFOLO\repo\pyupdater_source\tests\data\update_repo_extract\Acme"

:start
timeout /T 1 >>NUL
echo %%a%%

if %%a%% GEQ 30 (
goto stop
)

set /A a=%%a%%+1
if exist %%observable_file%% (
2>nul (
>> %%observable_file%%  (call )
) && (goto accessGranted) || (goto start) ) else ( exit )

:stop
echo "ACCESS TIMEOUT" >> %%appdata%%/extract_info_2.txt
goto end

:accessGranted
echo %a%
echo "FILE AVAILABLE" >> %appdata%/extract_info_2.txt
robocopy "C:\TRAFOLO\repo\pyupdater_source\tests\data\update_repo_extract\.update\update\Acme" "C:\TRAFOLO\repo\pyupdater_source\tests\data\update_repo_extract\Acme" /e /move /V > %appdata%/extract_info_1.txt
echo restarting... >> %appdata%/extract_info_2.txt

goto end


:end
DEL "%~f0"
                