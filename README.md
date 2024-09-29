# Pingviper
Just a dumb tool that automates ping sweeps and Nmap scans.

Usage

```
pingviper.sh [-h] [method] <Subnet> <Mask>
```

Methods

```
sweep              Perform Ping sweep to given subnet and mask
scan               Perform Nmap scans to file target
```

Options

```
-h                 Show this help message and exit
-v                 Enable verbose mode for Nmap output
-s                 Set subnet
-m                 Set mask
```
