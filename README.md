<p align=center>
  <br>
  <a href="https://github.com/arnold-vianna?tab=repositories" target="_blank"><img src="https://avatars.githubusercontent.com/u/113808475?v=4"/></a>
  <br>
  <span>check out my website <a href="https://arnold-vianna.github.io/">arnold-vianna.github.io</a></span>
  <br>
</p>



# Cheat Sheet Search Script With Web-UI

<a href="https://imgur.com/heaERZL"><img src="https://imgur.com/heaERZL.png" title="source: imgur.com" /></a>

## Key Features 
* User Management**: Admins can create, delete, and modify user accounts, including password changes (now supporting admin account updates) and generating unique API keys for secure external access.

--------

* Inventory Control**: Add, edit, and remove items with details like name, description, quantity, unit, tags, and optional images. Switch between card and list views for flexibility.

--------

* Permission System**: Role-based access with "read-only" (view-only) and "read-write" (full control) permissions to ensure data integrity.

---------

* API Integration**: Access inventory data via a RESTful endpoint (`/api/items`) in JSON format, protected by API key authentication.

---------

* Responsive Design**: A dark-themed, Bootstrap-powered UI ensures usability across devices with no configuration required.


----------
## Default Credentials

* admin
* 1pAxA}N@k$UgSDs3]\e/SmwN.g2dr5

--------
## Install Via Docker HUB


```console
docker pull arnoldvianna/inventory_manager
```

```console
docker run -d -p 5049:5049 arnoldvianna/inventory_manager
```

```console
http://localhost:5049/login
```




## Install Via Docker With The Github Repo

```console
git clone https://github.com/arnold-vianna/inventory_manager.git
```

```console
cd inventory_manager
```

```console
sudo docker build -t inventory_manager .
```

```console
sudo docker run -d -p 5049:5049 --name inventory-manager-instance inventory-manager
```

```console
http://0.0.0.0:5049
```




## Install On Linux

```console
git clone https://github.com/arnold-vianna/inventory-manager.git
```

```console
cd inventory-manager
```

```console
python3 -m venv venv_inventory-manager
```

```console
source venv_inventory-manager/bin/activate
```

```console
pip install -r requirements.txt
```

```console
gunicorn -w 2 -b 0.0.0.0:5049 app:app
```

```console
http://0.0.0.0:5049
```

## Usage

* Add remove items in the inventory 

* Add pictures amd tags to each entry

* can add multiple users





## Key Features

* No configuration needed 

* read-only users can monitor stock without altering data

* admin can oversee all operations, add users, manage api keys and more.




## Other information

The Inventory Management Web Application is a Flask-based, user-friendly system designed to streamline the management of inventory items and user accounts. Built with Python, SQLite, and Bootstrap, this application provides a secure and efficient platform for tracking items, managing user permissions, and generating API keys for programmatic access. It is tailored for small to medium-sized operations requiring a lightweight, customizable solution.

