# kubectl-secrets

A Python based kubectl plugin to print decoded Kubernetes secrets. Authentication is based on users kubeconfig as taken from `KUBECONFIG` environment variable.

This plugin aims to replace several long winded kubectl commands. e.g.

```
# find available secret keys
kubectl decscribe secret k8sregistry
# now get that key and decode the base64 string secret value
kubectl get secret k8sregistry -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d
```

is replaced by

```
# show all secret values, decoded
kubectl s90-dfsecrets k8sregistry
```

A character count saving of ~90

Options can be added to the plugin to help with finding secrets and printing out specific keys. This plugin will help speed up most investigations into secrets.

## Installation

**Written using Python 3.8.5, will require python >=3.6 to run**

* From Source

Get the repo and move the file into place

```
git clone https://github.com/schizoid90/s90-secrets.git
mkdir -r ~/.krew/store/s90-dfsecrets/1.1.1/
mv kubectl-s90-dfsecrets/src/* ~/.krew/store/s90-dfsecrets/1.1.1/
chmod +x ~/.krew/store/s90-dfsecrets/1.1.1/
```

## Usage

This script can be used as a kubectl plugin or stand alone, the options remain the same. You provide a namespace (or -A for all namespaces) and a secret name to view.

```shell
kubectl s90-dfsecrets -n namespace secret_name
```

or stand alone

```shell
python3 main.py -n namespace secret_name
```

If you wish to view all secrets in a namespace don't pass a secret name

```shell
kubectl s90-dfsecrets -n namespace
```

### Table Output

```
+-----------+-------------+-------------------+---------------------------------------------------------------------+
| Namespace   |    secret   |        key        | value                                                             |
+-------------+-------------+---------------------------------------------------------------------------------------+
|  namespace  | secret-name | secret-key        | base64 decoded secret value                                       |
+-----------+-------------+-------------------+---------------------------------------------------------------------+
```

### Raw Output

```
namespace/secret-name:
        secre-key: b'base64 decoded secret value'
```

### Options

```
usage: main.py [-h] [--version] [--namespace NS] [--all-namespaces]
               [--output {table,raw}] [--key SECRETKEY] [--list] [--list-keys]
               secret

Show decoded secrets information

positional arguments:
  secret

optional arguments:
  -h, --help            show this help message and exit
  --version, -v         show program's version number and exit
  --namespace NS, -n NS
                        Set namespace
  --output {table,raw}, -o {table,raw}
                        Output format: table or as raw (default) string
  --key SECRETKEY, -k SECRETKEY
                        Specify a key from the secret
  --list, -l            List secret names
  --list-keys, -L       List secret keys
```

## Known Issues

* **Table output for certificates**

When printing output to a table, certificates will show each line on a new table row. **Be sure not to use -o table for certificate secrets**

* **Duplicating output when listing secret names**

When using `--list` with `--output table` secrets will print multiple times (once per secret key). This is a minor issue but could result in lots of noise e.g. when printing all secrets in all namespaces

```shell
kubectl s90-dfsecrets '' -l -A -o table
```

With bash it is possible to reduce this noise by using `uniq`. A powershell alternative is probably available.

```shell
kubectl s90-dfsecrets '' -l -A -o table | uniq
```

* **Listing secrets with no data**

Sometimes you may receive an error:

```python
'NoneType' object is not iterable
Check for empty secrets
```

This is caused by a secret containing no data. In this instance you will need to specify non empty secrets to inspect. 

**Do not indiscriminately delete secrets with no data, they may still be required by some apps**

## Future

* Find what pods a secret is used in
* Manipulate secrets (add, delete, edit)
