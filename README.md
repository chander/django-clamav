# django-clamav

This is a fork of https://github.com/vstoykov/django-clamd with some minor customizations.

This project integrates python-clamd with Django for easy scanning files for viruses on upload


## Installation

Install `django-clamav` package.

    pip install git+https://github.com/QueraTeam/django-clamav.git

Aditioanlly if you want translations to work you need to add it to installed apps.

    INSTALLED_APPS = (
        ...
        'django_clamav',
        ...
    )


## Usage

You can use it in forms:

    from django import forms
    from django_clamav.validators import validate_file_infection

    class UploadForm(forms.Form):
        upload_file = forms.FileField(validators=[validate_file_infection])

Or you can add it as validator directly in your model:

    from django.db import models
    from django_clamav.validators import validate_file_infection

    class FileModel(models.Model):
        document = models.FileField(validators=[validate_file_infection])

You will have automatically scanning of upladed files in Django Admin
and also when create ModelForm's for that model.


Configuration
-------------

By default `django-clamav` tries to be smart and with good defaults.
You can still configure how to connect to Clamd. Default values are:

    CLAMAV_UNIX_SOCKET = '/var/run/clamav/clamd.ctl'
    CLAMAV_USE_TCP = False
    CLAMAV_TCP_PORT = 3310
    CLAMAV_TCP_ADDR = '127.0.0.1'
    CLAMAV_MAX_FILE_SIZE = 2147483648 # 2GB (Maximum size file to be scanned)

Note: When you are running on Fedora or CentOS and :code:`clamav-scanner`
package is installed then default value for :code:`CLAMAV_UNIX_SOCKET` is:

    CLAMAV_UNIX_SOCKET = '/var/run/clamd.scan/clamd.sock'

You also can disable virus scanning for development with:

    CLAMAV_ENABLED = False

Note: This is primary for make it easy to run a project on development without
the need of installing Clamd on devlopment machine.


License
-------
`django-clamav` is released as open-source software under the LGPL license.
