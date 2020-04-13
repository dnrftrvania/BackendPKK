<?php

namespace App\Http\Controllers;

use App\Montir;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class CustomerController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid_credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'could_not_create_token'], 500);
        }
        return response()->json(compact('token'));
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'nama_montir' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:customer',
            'password'  => 'required|string|min:6',
            'kontak'  => 'required|string|min:11',
            'nama_perusahaan' => 'required|string|max:255',
            'alamat_perusahaan' => 'required|string|max:255'
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $montir = Montir::create([
            'nama_montir'  => $request->get('nama_montir'),
            'email'  => $request->get('email'),            
            'password'  => Hash::make($request->get('password')),
            'kontak'  => $request->get('kontak'),
            'nama_perusahaan' => $request->get('nama_perusahaan'),
            'alamat_perusahaan' => $request->get('alamat_perusahaan'),
        ]);
        $token = JWTAuth::fromMontir($montir);
        return response()->json(compact('montir','token'), 201);
    }

    public function getAuthenticatedMontir()
    {
        try {
            if(! $customer = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['montir_not_found'], 404);
            }
        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['token_expired'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
            return response()->json(['token_invalid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['token_absent'], $e->getStatusCode());
        }
        return response()->json(compact('montir'));
    }

    public function logins(Request $request){
		$credentials = $request->only('email', 'password');

		try {
			if(!$token = JWTAuth::attempt($credentials)){
				return response()->json([
						'logged' 	=>  false,
						'message' 	=> 'Invalid email and password'
					]);
			}
		} catch(JWTException $e){
			return response()->json([
						'logged' 	=> false,
						'message' 	=> 'Generate Token Failed'
					]);
		}
		return response()->json([
					"logged"    => true,
                    "token"     => $token,
                    "message" 	=> 'Login berhasil'
		]);
	}
}
