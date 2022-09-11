# DayZ_LocalHost (using DayZDiag_x64.exe)
Play DayZ or test mods offline on your PC.

# INSTRUCTIONS
Start one of the batch files
"DZ_localhost.bat" (starts local server only)
"DZ_localhost+logmonitor.bat" (same as above: starts server only but keeps the commandline window open to monitor the server logs)
"DZ_localhost+client.bat" (starts server and client that connects to the server)
"DZ_localhost+client+logmonitor.bat" (same as above: starts server and client that connects to the server but keeps the commandline window open to monitor the server logs)

All batch files start the "DayZDiag_x64.exe" using the powershell script "DZ_server.ps1".
Depending on what batch you started it will start the "DayZDiag_x64.exe" a second time as client automatically connecting to that local server.

It doesn't matter where you put all this.
The script should run out of the box. 
It will find Steam and DayZ install directories automatically,.
It will check if steam/dayzserver/dayzclient is running and if not start it.
By default it will start plain vanilla chernarusplus with default game settings. (there is one template "vanilla.chernarusplus" that will be used by default; this is where all the persistent stuff is stored)
So there is no setup or config needed.
However if you have specific requirements read below...
 
# LOGFILES / PROFILES
The script does not use a sepcial client profile. 
In fact your default DayZ game profile will be used which should be the current windows user.
This way you don't have to configure any game settings like keybindings or graphics etc.
(by default this should be %userprofile%\Documents\DayZ)
 
However the script does use a certain server profile to separate clients settings/logs from server related stuff.
The server profile is %userprofile%\Documents\DayZServer
This is the profile folder where you will find logs and where you put all serverside settings for mods etc.
 
#CUSTOM MISSIONS
If you want to change the map, edit the "DZ_server_params.ini" and add the line 
mission = "path/to/your/mission"
 
additionally edit the DZ_server.cfg and change the template to match your desired map. 
(See bottom of DZ_server.cfg)
 
# SCRIPTING
If you use scripting and within your scripts refer to $CurrentDir when including other scripts
your missions directory must be a subdirectory of the DayZ install directory 
since $CurrentDir always points to that dir.
Otherwhise your map can be wherever you want as long as you use an absolute path for the param "mission" in the ini file.
 
# MODS
Edit the DZ_server_params.ini to add mods. (one per line)
Notice that your mods need to be relative to the DayZ install directory.
That means you have to include the workshop directory as well: "!Workshop\@YourMod"
