## Install

This is a mandatory plugin, shipped with FIR. Therefore, it is installed by default.

## Usage

This plugin is responsible for all the artifacts magic. It defines five default artifact types:

* Emails
* Hashes
* Hostnames
* IP addresses
* URLs

Each artifact type will be automatically generated by looking into the incident description, the comments, or the nuggets.

It creates a tab in the incident details view, listing all the associated artifacts.

All "correlated artifacts" (i.e. artifacts that appear in more than one incident), if any, will be colored in red and will have a special display at the top-right corner of the incident details view.

## Development

You can easily create your own artifacts types with little effort. All you have to do is create your own plugin (mimicking the structure of `fir_artifacts`, and create a class that inerhits from `AbstractArtifact`. Here's an example:

### Basic constructs

Let's say we want to create a basic artifact type for banking account numbers. To avoid false positives, we would like to limit detections to any number of digits that are following the text `Account: `. All we have to do is create the following file:

```python
from fir_artifacts.artifacts import AbstractArtifact


class AccountNumber(AbstractArtifact):
	key = "account"
	display_name = "Accounts"
	regex = r"(Account)[ \xa0]?:[ \xa0]?(?P<search>[\d]+)"
```

* `key` is what references this type of artifacts internally, it should be unique.
* `display_name` is what will be displayed in the views.
* `regex` is the regular expression used to detect artifacts in text. The value of the artifact will be taken from the `search` named group.

Then, you need to install your artifact, in the `__init__.py` file for your plugin:

```python
from fir_artifacts import artifacts
from my_custom_plugin.account_number import AccountNumber


artifacts.install(AccountNumber)
```

### Advanced constructs

In most cases, this is all you will need to define your own artifacts. But if this doesn't suit your needs, you can use more advanced constructs.

You can define the following class variables:

* `case_sensitive`: when set to `False` (default), the artifact values will be converted to lowercase prior to being saved in the database.
* `template`: allows you to define your own template for artifact displays. You should look at the default template in `fir_artifacts/templates/fir_artifacts/default.html` in order to understand how to write your own template.

You can also define the following class methods:

* `find(cls, data)`: should search for artifacts in data and return a list of artifact values. By default, it is using the `regex` class variable to automatically parse the data.
* `after_save(cls, value, event)`: this will be called after all the parsed artifacts have been saved. `value` is the artifact value, and `event` the event or incident from which the artifact was created. This can be useful in cases where post-treatment is to be applied to the artifacts (e.g. pushing them on a thir-party service, run asynchronous analytics, etc.). By default, this does nothing.
