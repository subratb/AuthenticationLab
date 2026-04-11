# Install dotnet on Kali Linux

Get the `install` script.
```bash
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
```
or, with `curl`
```bash
curl -L https://dot.net/v1/dotnet-install.sh -o dotnet-install.sh
```
Grant executable permission to the script
```bash
chmod +x ./dotnet-install.sh
```
Install latest long-term(`LTS`) supported version of `dotnet`.
```bash
./dotnet-install.sh --version latest
```
To install `dotnet` runtime only, use the `--runtime` parameter.
```bash
./dotnet-install.sh --version latest --runtime aspnetcore
```
To add globalization support install `libicu-dev`.
```bash
apt install libicu-dev
```
Run `dotnet` commands as shown:
```bash
# Change to directory where dotnet is installed
cd /root/.dotnet

# Execute dotnet like so:
./dotnet -h
```
Run `C#` Files as Scripts
```bash
./dotnet run Crack.cs
```

## Reference

1. [Scripted Install](https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual#scripted-install)

### TODO

1. Setup `dotnet` in `PATH`