use Illuminate\Support\Facades\Route;
use App\Modules\Auth\Controllers\AuthController;

Route::group(['namespace' => 'App\Modules\Auth\Controllers', /*'prefix' => 'auth',*/ 'middleware' => ['web']], function() {
    Route::get('/login', 'AuthController@login')->name('login');
    Route::get('/register', 'AuthController@register')->name('register');
    Route::post('/register-user', 'AuthController@registerUser');
    Route::post('/login-user', 'AuthController@loginUser');
    Route::get('/sendOTP', 'AuthController@sendOTP');
    Route::post('user-authenticate', 'AuthController@userAuthenticate');
    Route::post('user-authorization', 'AuthController@userAuthorization');
    Route::post('logout', 'AuthController@logout')->name('logout');

});

Route::post('update-user-password', 'App\Modules\Auth\Controllers\AuthController@updateUserPassword');
Route::post('update-user-profile', 'App\Modules\Auth\Controllers\AuthController@updateUser');

Route::get('/verifyOTP', 'AjaxController@verifyOTP');
Route::get('/change_password', 'AjaxController@change_password');
