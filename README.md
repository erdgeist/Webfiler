Webfiler
========

This project leverages the powers of Flask and Flask-Dropzone to provide for a simple self hosted user upload space manager.

If you're a lawyer, doctor, or have a small company and need your clients/patients/customers to share some documents with you (and only you), you can create spaces for them with just a click, pass them their passwords and use your and their web browsers as upload and file list interface. Each installation also gets a Public space for your documents to share with everyone.

Installation
============

Currently, Webfiler comes with a Makefile which sets everything up for you. After cloning the project, just type `make run` and after installing all dependencies, a sneak preview server will run at http://localhost:5000/. This will also create work directories under a data directory that defaults to './Daten'.

Web server integration
======================

Webfiler generates htpasswd files to protect your spaces. Webfiler has a [sample nginx config](nginx.conf.sample) you can use.

License
=======

Webfiler is released under Beerware.
