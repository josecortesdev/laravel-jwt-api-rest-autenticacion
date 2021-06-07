<?php

namespace App\Http\Controllers;

    use App\Models\User;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Hash;
    use Illuminate\Support\Facades\Validator;
    use JWTAuth;
    use Tymon\JWTAuth\Exceptions\JWTException;

    use Illuminate\Http\JsonResponse;
    use Symfony\Component\HttpFoundation\Response;

class UserController extends Controller
{
    public function authenticate(Request $request)
    {
    
    // solo acepta email y password
    $credentials = $request->only('email', 'password');
    try {
        // si no es correcto
        if (! $token = JWTAuth::attempt($credentials)) {
            return response()->json(['error' => 'invalid_credentials'], 400);
        }
    } catch (JWTException $e) {
        return response()->json(['error' => 'could_not_create_token'], 500);
    }
    //si todo va bien, devuelve el token
    return response()->json(compact('token'));
    }

    public function getAuthenticatedUser()
    {
    try {
        // Si no puede autenticarse:
        if (!$user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
        }
        // Otras cosas que pueden ocurrir:
        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
                return response()->json(['token_expired'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
                return response()->json(['token_invalid'], $e->getStatusCode());
        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {
                return response()->json(['token_absent'], $e->getStatusCode());
        }

        //Devuelve user
        return response()->json(compact('user'));
    }

    //Registro
    public function register(Request $request)
    {
        // Validación
            $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        // Si hay error...
        if($validator->fails()){
                return response()->json($validator->errors()->toJson(), 400);
        }

        // Crear usuario
        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'password' => Hash::make($request->get('password')),
        ]);

        $token = JWTAuth::fromUser($user);

        //Devuelve el usuario creado y el token
        return response()->json(compact('user','token'),201);
    }

    public function logout(Request $request)
    {
        $token = $request->header( 'Authorization' ); // el token

        JWTAuth::parseToken()->invalidate( $token ); // invalida el token
       // auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

}
