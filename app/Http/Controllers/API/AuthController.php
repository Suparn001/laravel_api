<?php

namespace App\Http\Controllers\API;

use App\Models\User;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function signup(Request $request)
    {
        $validateUser = Validator::make(
            $request->all(),
            [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required',

            ]
        );
        if ($validateUser->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Validation Error',
                'errors' => $validateUser->errors()->all()
            ], 401);
        } else {
            $user = User::create(
                [
                    'name' => $request->name,
                    'email' => $request->email,
                    'password' => $request->password,
                ]
            );
            return response()->json([
                'status' => true,
                'message' => 'User Created Successfully',
                'user' => $user,
            ], 200);
        }
    }

    public function login(Request $request)
    {
        $validateUser = Validator::make(
            $request->all(),
            [
                'email' => 'required|email',
                'password' => 'required',
            ]
        );
        if ($validateUser->fails()) {
            return response()->json([
                'status' => false,
                'message' => 'Authentication Error',
                'errors' => $validateUser->errors()->all()
            ], 404);
        }
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $authUser = Auth::user();
            return response()->json([
                'status' => true,
                'message' => 'User Login Successfully',
                'token' => $authUser->createToken("API_TOKEN")->plainTextToken,
                'token_type' => 'bearer'
            ], 200);
        } else {
            return response()->json([
                'status' => false,
                'message' => 'Authentication Error',

            ], 401);
        }
    }

    public function logout(Request $request)
{
    // Get the authenticated user
    $user = $request->user();
    
    // Delete all tokens associated with the user
    $user->tokens()->delete(); // here since i havenot specified any particular toke, therefore it will delete all tokens related to that user 

    return response()->json([
        'status' => true,
        'user' => $user,
        'message' => 'You logged out successfully',
    ], 200);
}
}
