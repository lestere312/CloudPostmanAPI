from google.cloud import datastore
from flask import Flask, request, jsonify, render_template
from requests_oauthlib import OAuth2Session

from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests


app = Flask(__name__)
client = datastore.Client()

scope = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']


CLIENT_ID = ""

CLIENT_SECRET = ""

REDIRECT_URI = ''





oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=scope)



@app.route('/')
def index():
	print("id_info")
	authorization_url, state = oauth.authorization_url(
		'https://accounts.google.com/o/oauth2/auth',
		access_type="offline", prompt="select_account")
	return render_template("index.html",title="Final CS493 Assignment", login=authorization_url)

@app.route('/oauth')
def oauthroute():
	token = oauth.fetch_token('https://accounts.google.com/o/oauth2/token', authorization_response=request.url, client_secret=CLIENT_SECRET)
	req = requests.Request()
	id_info = id_token.verify_oauth2_token(token['id_token'], req, CLIENT_ID)

	query = client.query(kind="users")
	query.add_filter("sub", "=", id_info['sub'])
	result = list(query.fetch())
	if len(result) == 0:
		new_user = datastore.entity.Entity(key=client.key('users'))
		new_user.update({'email': id_info['email'], 'sub': id_info['sub']})
		client.put(new_user)

		query = client.query(kind="users")
		query.add_filter("sub", "=", id_info['sub'])
		results = list(query.fetch())

		return render_template("user_info.html", state=token['id_token'], fname=results[0], title="Account Created")
	elif len(result) == 1:

		query = client.query(kind="users")
		query.add_filter("sub", "=", id_info['sub'])
		results = list(query.fetch())

		return render_template("user_info.html", state=token['id_token'], fname=results[0], title="Welcome")
	return render_template("error.html", title="There was an error")

@app.route('/users/<uid>', methods=['GET'])
def get_user_id(uid):
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	if request.method == 'GET':
		req = requests.Request()
		jwt_token = request.headers.get('Authorization')
		if jwt_token:
			jwt_token = jwt_token.split(" ")[1]
			print("jwt_token")
			print(jwt_token)
			try:
				jwt_sub = id_token.verify_oauth2_token(jwt_token, req, CLIENT_ID)['sub']
			except:
				return(jsonify({'Error':'Could not verify JWT\n'}), 401)
		else:
			return (jsonify({'Error': 'no JWT given'}), 401)

		print(jwt_sub)
		print("jwt_sub")


		query = client.query(kind="users")
		query.add_filter("sub", "=", jwt_sub)
		results = list(query.fetch())

		print(results)
		print("results")

		if len(results) == 0:
			return(jsonify({'Error': 'This user does not exist!\n'}), 404)

		for entity in results:
			entity["id"] = entity.key.id
			entity["self"] = request.url

		return (jsonify(results), 200)

@app.route('/users', methods=['GET'])
def get_users():
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	if request.method == 'GET':
		query = client.query(kind="users")
		results = list(query.fetch())

		for entity in results:
			entity["id"] = entity.key.id
			entity["self"] = request.url + "/" + str(entity.key.id)

		return (jsonify(results), 200)


@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	if request.method == 'POST':
		req = requests.Request()
		jwt_token = request.headers.get('Authorization')
		if jwt_token:
			jwt_token = jwt_token.split(" ")[1]
			try:
				jwt_sub = id_token.verify_oauth2_token(jwt_token, req, CLIENT_ID)['sub']
			except:
				return(jsonify({'Error':'Could not verify JWT\n'}), 401)
		else:
			return (jsonify({'Error': 'no JWT given'}), 401)

		content = request.get_json()
		if len(content) != 4:
			return (jsonify({"Error": "not enough attributes"}), 400)

		new_boat = datastore.entity.Entity(key=client.key("boats"))
		new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "public": "false", "owner": jwt_sub, 'loads': []})
		client.put(new_boat)

		temp_self = request.url + "/" + str(new_boat.key.id)
		return (jsonify({"id": new_boat.key.id, "name": content["name"], "type": content["type"], "length": content["length"], "public": "false", "owner": jwt_sub, "self": temp_self }), 201)
	elif request.method == 'GET':
		public = False
		req = requests.Request()
		jwt_token = request.headers.get('Authorization')

		if jwt_token:
			jwt_token = jwt_token.split(" ")[1]
			try:
				jwt_sub = id_token.verify_oauth2_token(jwt_token, req, CLIENT_ID)['sub']
			except:
				public = True
		else:
			public = True


		query = client.query(kind="boats")
		if public:
			query.add_filter("public", "=", True)
		else:
			query.add_filter("owner", "=", jwt_sub)
		results = list(query.fetch())

		for entity in results:
			entity["id"] = entity.key.id
			entity["self"] = request.url + "/" + str(entity.key.id)



		#query = client.query(kind="boats")
		q_limit = int(request.args.get('limit', '5'))
		q_offset = int(request.args.get('offset', '0'))
		l_iterator = query.fetch(limit= q_limit, offset=q_offset)
		pages = l_iterator.pages
		results = list(next(pages))
		if l_iterator.next_page_token:
			next_offset = q_offset + q_limit
			next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
		else:
			next_url = None
		for e in results:
			e["id"] = e.key.id
			e["self"] = request.url + '/' + str(e.key.id)
			if len(e['loads']) > 0:
				for single_load in e['loads']:
					single_load['self'] = request.url_root + "loads/" + str(single_load['id'])
		output = {"boats": results}
		if next_url:
			output["next"] = next_url
		return (jsonify(output), 200)





		#return render_template("user_boats.html", list=results)
		return (jsonify(results), 200)
	else:
		return (jsonify('Method not Allowed'), 405)



@app.route('/boats/<boat_id>', methods=['PUT','DELETE','GET','PATCH'])
def manip_boat(boat_id):
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	req = requests.Request()
	jwt_token = request.headers.get('Authorization')
	if jwt_token:
		jwt_token = jwt_token.split(" ")[1]
		try:
			jwt_sub = id_token.verify_oauth2_token(jwt_token, req, CLIENT_ID)['sub']
		except:
			return(jsonify({'Error': 'Could not verify JWT\n'}), 401)
	else:
		return (jsonify({'Error': 'no JWT given'}), 401)

	if request.method == 'DELETE':
		boat_key = client.key("boats", int(boat_id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({'Error': 'boat does not exist'}), 404)
		elif boat['owner'] != jwt_sub:
			return (jsonify({'Error': 'you do not have ownership of this boat'}), 401)
		if len(boat['loads']) > 0:
			for load in boat['loads']:
				load_obj = client.get(key=client.key("loads", load['id']))
				load_obj['carrier'] = None
				client.put(load_obj)
		client.delete(boat_key)
		return (jsonify(''), 204)
	elif request.method == 'GET':
		boat_key = client.key("boats", int(boat_id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		elif boat['owner'] != jwt_sub:
			return (jsonify({'Error': 'you do not have ownership of this boat'}), 401)
		for load in boat['loads']:
			load["self"] = request.url_root + "loads/" + str(load['id'])
		boat["id"] = boat_id
		boat["self"] = request.url
		return (jsonify(boat), 200)
	elif request.method == 'PATCH':
		content = request.get_json()
		#print(content)
		if len(content) < 1:
			return (jsonify({"Error": "The request object is missing at least one attribute"}), 400)


		boat_key = client.key("boats", int(boat_id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)

		if "name" in content:
			cont = content["name"]
		else:
			cont = boat["name"]

		if "type" in content:
			cont2 = content["type"]
		else:
			cont2 = boat["type"]

		if "length" in content:
			cont3 = content["length"]
		else:
			cont3 = boat["length"]

		boat.update({"name": cont, "type": cont2, "length": cont3})
		client.put(boat)
		return (jsonify({"id": boat.key.id, "name": cont, "type": cont2, "length": cont3,"public": "false", "owner": jwt_sub, "self": str(request.url)}), 202)
	elif request.method == 'PUT':
		content = request.get_json()

		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)


		try:
			boat_key = client.key("boats", int(boat_id))
		except ValueError:
			return (jsonify({"Error": "not a valid id"}), 400)
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No boat with this boat_id exists"}), 404)
		boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
		client.put(boat)

		response = jsonify({"id": boat.key.id, "name": content["name"], "type": content["type"], "length": content["length"],"public": "false", "owner": jwt_sub, "self": str(request.url)})
		response.status_code = 202
		response.headers['location'] = str(request.url)
		response.autocorrect_location_header = False
		return response
	else:
		return (jsonify('Method not Allowed'), 405)



@app.route('/delete', methods=['delete'])
def delete_all():
	query = client.query(kind="boats")
	results = list(query.fetch())
	for entity in results:
		#entity["name"]
		boat_key = client.key("boats", entity.key.id)
		client.delete(boat_key)
	query = client.query(kind="loads")
	results = list(query.fetch())
	for entity in results:
		boat_key = client.key("loads", entity.key.id)
		client.delete(boat_key)
	return (jsonify('Reseting all varibles'),204)

@app.route('/deleteusers', methods=['delete'])
def delete_users():
	query = client.query(kind="users")
	print("query")
	print(query)
	results = list(query.fetch())
	for entity in results:
		boat_key = client.key("users", entity.key.id)
		client.delete(boat_key)
	return (jsonify('Reseting all varibles'),204)

@app.route('/owners/<owner_id>/boats', methods=['GET'])
def boats_get(owner_id):
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	if request.method == 'GET':
		public = False
		req = requests.Request()
		jwt_token = request.headers.get('Authorization')
		if jwt_token:
			jwt_token = jwt_token.split(" ")[1]
			try:
				jwt_sub = id_token.verify_oauth2_token(jwt_token, req, CLIENT_ID)['sub']
			except:
				public = True
		else:
			public = True
		query = client.query(kind="boats")
		if(public):
			query.add_filter("public", "=", True)
		query.add_filter("owner", "=", owner_id)
		results = list(query.fetch())
		for entity in results:
			entity["id"] = entity.key.id
		return (jsonify(results), 200)
		return render_template("user_boats.html", list=results)

@app.route('/loads', methods=['POST','GET'])
def loads_get_post():
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	if request.method == 'POST':
		content = request.get_json()
		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		new_load = datastore.entity.Entity(key=client.key("loads"))
		new_load.update({"weight": content["weight"], 'carrier': None, 'content': content['content'], 'radioactive': content['radioactive']})
		client.put(new_load)
		new_load['id'] = new_load.key.id
		new_load['self'] = request.url + '/' + str(new_load.key.id)
		return (jsonify(new_load), 201)
	elif request.method == 'GET':
		query = client.query(kind="loads")
		q_limit = int(request.args.get('limit', '5'))
		q_offset = int(request.args.get('offset', '0'))
		g_iterator = query.fetch(limit= q_limit, offset=q_offset)
		pages = g_iterator.pages
		results = list(next(pages))
		if g_iterator.next_page_token:
			next_offset = q_offset + q_limit
			next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
		else:
			next_url = None
		for e in results:
			e["id"] = e.key.id
			e["self"] = request.url_root + "loads/" + str(e.key.id)
			if e["carrier"] != None:
				e['carrier']['self'] = request.url_root + "boats/" + str(e['carrier']['id'])
		output = {"loads": results}
		if next_url:
			output["next"] = next_url
		return (jsonify(output), 200)

@app.route('/loads/<id>', methods=['DELETE','GET','PATCH','PUT'])
def loads_get_delete(id):
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	if request.method == 'DELETE':
		key = client.key("loads", int(id))
		load = client.get(key=key)
		if load == None:
			return (jsonify({"Error": "No load with this load_id exists"}), 404)
		if load['carrier'] != None:
			boat = client.get(key=client.key("boats", load['carrier']['id']))
			boat["loads"].remove({'id': load.key.id})
			client.put(boat)
		client.delete(key)
		return (jsonify(''),204)
	elif request.method == 'GET':
		load_key = client.key("loads", int(id))
		load = client.get(key=load_key)
		if load == None:
			return (jsonify({"Error": "No load with this load_id exists"}), 404)
		if load["carrier"]:
			load["carrier"]["self"] = request.url_root + "boats/" + str(load["carrier"]["id"])
		load["id"] = id
		load["self"] = request.url
		return (jsonify(load), 200)

	elif request.method == 'PATCH':
		content = request.get_json()
		#print(content)
		if len(content) < 1:
			return (jsonify({"Error": "The request object is missing at least one attribute"}), 400)


		boat_key = client.key("loads", int(id))
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No load with this id exists"}), 404)

		if "content" in content:
			cont = content["content"]
		else:
			cont = boat["content"]

		if "radioactive" in content:
			cont2 = content["radioactive"]
		else:
			cont2 = boat["radioactive"]

		if "weight" in content:
			cont3 = content["weight"]
		else:
			cont3 = boat["weight"]

		boat.update({"content": cont, "radioactive": cont2, "weight": cont3})
		client.put(boat)
		return (jsonify({"id": boat.key.id, "content": cont, "radioactive": cont2, "weight": cont3,"public": "false", "self": str(request.url)}), 202)
	elif request.method == 'PUT':
		content = request.get_json()

		if len(content) != 3:
			return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)


		try:
			boat_key = client.key("loads", int(id))
		except ValueError:
			return (jsonify({"Error": "not a valid id"}), 400)
		boat = client.get(key=boat_key)
		if boat == None:
			return (jsonify({"Error": "No loads with this id exists"}), 404)
		boat.update({"content": content["content"], "radioactive": content["radioactive"], "weight": content["weight"]})
		client.put(boat)

		response = jsonify({"id": boat.key.id, "content": content["content"], "radioactive": content["radioactive"], "weight": content["weight"],"public": "false", "self": str(request.url)})
		response.status_code = 202
		response.headers['location'] = str(request.url)
		response.autocorrect_location_header = False
		return response

	else:
		return (jsonify('Method not Allowed'), 405)




@app.route('/<bid>/loads/<lid>', methods=['PUT','DELETE'])
def add_put(bid, lid):
	if 'application/json' not in request.accept_mimetypes:
		return (jsonify({"Error" : "only accept JSON request"}), 406)
	if request.method == 'PUT':
		boat_key = client.key("boats", int(bid))
		boat = client.get(key=boat_key)
		load_key = client.key("loads", int(lid))
		load = client.get(key=load_key)
		if boat == None or load == None:
			return (jsonify({"Error": "No boat/load with this id exists"}), 404)
		if load['carrier'] != None:
			return (jsonify({"Error": "Load already assigned to boat"}), 403)
		if 'loads' in boat.keys():
			for loads in boat['loads']:
				if loads['id'] == load.key.id:
					return(jsonify({"Error": "Load already assigned to boat"}), 403)
			boat['loads'].append({"id": load.key.id})
			load['carrier'] = {"id": boat.key.id, "name": boat["name"]}
		else:
			boat['loads'] = {"id": load.key.id}
			load['carrier'] = {"id": boat.key.id, "name": boat["name"]}
		client.put(boat)
		client.put(load)
		return(jsonify(''), 204)
	if request.method == 'DELETE':
		boat_key = client.key("boats", int(bid))
		boat = client.get(key=boat_key)
		load_key = client.key("loads", int(lid))
		load = client.get(key=load_key)
		if boat == None or load == None:
			return (jsonify({"Error": "No boat/load with this id exists"}), 404)
		if load['carrier'] == None or load['carrier']['id'] != boat.key.id:
			return (jsonify({"Error": "This load is not on the boat"}), 404)
		if 'loads' in boat.keys():
			boat['loads'].remove({"id": load.key.id})
			load['carrier'] = None
			client.put(boat)
			client.put(load)
		return(jsonify(''),204)
	else:
		return (jsonify('Method not Allowed'), 405)




if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)
