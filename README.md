anno-lambda-authorizer
======================

* [What is this?](#what-is-this)
* [Assumptions](#assumptions)
* [What's in here?](#whats-in-here)
* [Bootstrap the project](#bootstrap-the-project)
* [Run the project](#run-the-project)

What is this?
-------------

AWS lambda function that serves as a custom authorizer for AWS API Gateway, its main purpose is to secure some Gateway endpoints.

This is a work in progress repo.

Assumptions
-----------

The following things are assumed to be true in this documentation.

* You are running OSX.
* You are using Python 2.7. (Probably the version that came OSX.)
* You have [virtualenv](https://pypi.python.org/pypi/virtualenv) and [virtualenvwrapper](https://pypi.python.org/pypi/virtualenvwrapper) installed and working.
* You have NPR's AWS credentials stored as environment variables locally.

For more details on the technology stack used with the app-template, see our [development environment blog post](http://blog.apps.npr.org/2013/06/06/how-to-setup-a-developers-environment.html).

What's in here?
---------------

The project contains the following folders and important files:

* ``code`` -- Where are lambda function code lives
* ``test``-- local tests to check that our code runs locally
* ``fabfile.py`` -- [Fabric](http://docs.fabfile.org/en/latest/) commands for automating setup and deployment
* ``requirements.txt`` -- Python requirements.

Bootstrap the project
---------------------

Create a lambda function inside AWS using the AWS Console and write down the name you gave to that function and

Also write down the name ot the handler you used.

For example if you have used `lambda.lambda_handler` then you will need to create a file on `code` called `lambda.py` that should have a function with name `lambda_handler` in it, that receives as arguments an `event` and a `context`. That will be the entry point for your lambda execution.

To bootstrap the project:

```
cd anno-lambda-authorizer
mkvirtualenv anno-lambda-authorizer
pip install -r requirements.txt
```

Run the project
---------------

* Review the code for your lambda function, include all the required libraries in `code/requirements.txt`

Since some of the code on this repo should be identical to that of the origin [anno-docs repo](https://github.com/nprapps/anno-docs) there's a fabric task that will grab the latest pushed files from `master` and place them in their corresponding place in the `code` folder. To sync those files run manually:

```
fab sync_anno_docs_files
```

* Create a function in your AWS lambda environment.

* Finally run:

```
fab deploy:function=FUNCTION_NAME
```

Where `FUNCTION_NAME` is the name of the created lambda function

_The deploy function automatically invokes the sync task mentioned above._




