dotnet publish -c Release -f net10.0 -r linux-x64 --no-self-contained
Compress-Archive -Path .\bin\Release\net8.0\linux-x64\publish\* -DestinationPath OpenPGP.zip -update