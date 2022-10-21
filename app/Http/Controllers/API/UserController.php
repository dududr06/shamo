<?php

namespace App\Http\Controllers\API;


use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function register(Request $request)
    {
        try{
            $validator = Validator::make($request->all(),[
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255'],
                'email' => ['required', 'string', 'email', 'max:255'],
                'password' => ['required', 'string', new Password]
            ]);

            User::create([
                'name'=>$request->name,
                'username'=>$request->username,
                'email'=>$request->email,
                'phone'=>$request->phone,
                'password'=>Hash::make($request->password)
                
            ]);
            
            $user = User::where('email', $request->email)->first();
            $tokenResult = $user->createToken('authToken')->plainTextToken;
            return ResponseFormatter::success([
                'access_token'=> $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');
    
            if($validator->fails()){
                return response()->json($validator->error(),400);
            }
        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message'=> 'something went wrong',
                'error' => $error
            ], 'Authentication failed ', 500);
        }
    }

    public function login(Request $request)
    {
        try {
           $request->validate([
            'email'=>'email|required',
            'password'=>'required'
           ]);

           $credentials = request(['email','password']);
           if(!Auth::attempt($credentials)){
                return ResponseFormatter::error([
                    'message'=>'Unauthorized'
                    ],'Authentication Failed', 500 
                );
           }

           $user = User::where('email', $request->email)->first();
           
           if(!Hash::check($request->password, $user->password, [])){
                throw new \Exception('Invalid Credentials');
           }

           $tokenResult = $user->createToken('authToken')->plainTextToken;

           return ResponseFormatter::success([
                'access_token'=> $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
           ], 'Authenticated');

        } catch (Exception $error) {
            return ResponseFormatter::error([
                'message'=>'Some thing went wrong',
                'error' => $error,
                ],'Authentication Failed', 500 
            );
        }
    }

    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(),'Data profile berhasil diambil');
    }

    public function updateProfile(Request $request)
    {
       
        $data = $request->all();
        $request->validate([
            'email'=>'email|required',
        ]);

        $user = Auth::user();
        $user->update($data);
        return ResponseFormatter::success($user, 'Profile Updated');
    }

    public function logout(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();

        return ResponseFormatter::success($token,'Token Revoked');
    }
}
