<?php

namespace Shitein\Auth\Controllers;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\App;
use App\Http\Controllers\Controller;
use Carbon\Carbon;
use App\Company;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use App\common\Common;
use App\Http\Controllers\Base\CommonBaseController;
use App\Http\Controllers\EmailMasterController;
use App\Http\Controllers\UserController;
use App\Modules\Auth\Models\MasterModel;
use App\Modules\Auth\Models\OtpModel;
use App\Modules\Auth\Models\RoleModel;
use App\Modules\Auth\Models\LoggingReport;
use App\Modules\Auth\Models\User;
//use App\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;
use Exception;
use Faker\Provider;
use phpDocumentor\Reflection\Types\Self_;

class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request) {
        try {
            return view('auth::login');
        } catch(\Exception $ex) {
            print_r($ex->getMessage());exit;
        }
    }

    /**
     * display a register view from resource
     *
     * @param  mixed $request
     * @return void
     */
    public function register(Request $request) {
        try {
            return view('auth::register');
        } catch(\Exception $ex) {
            print_r($ex->getMessage());exit;
        }
    }

    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'mobile_no' => ['required', 'string', 'max:10', 'unique:users'],
            'captcha_input' => ['required', 'required_with:captcha', 'same:captcha'],
            'captcha' => ['required'],
        ]);
    }

/* to register the user */
    public function registerUser(Request $request)
    {
        try {
            // dd($request->all());
            /*if (empty($request['registration_prevention'])) {

                $validator = $this->validator($request->all());

                if ($validator->fails()) {
                    return redirect(url()->previous())
                        ->withErrors($validator)
                        ->withInput();
                }

                event(new Registered($user = $this->create($request->all())));

                return redirect()->route('login')->with('success', 'Your Account Created successfully, Check email for password.');
            } else {
                return redirect()->route('register')->with('failed', 'Failed to Register');
            }*/
           // $response = UserController::createUser($request);
            $response = self::createUser($request);
           // dd($response);
            if($request->ajax()){
                return $response;
            } else {
                if(!empty($response['exception'])) {
                    return back()
                        ->withInput($request->input())
                        ->withErrors($response['exception']);
                }
                return redirect('/login?otp=true')->withInput($request->input())->with('success','Your Account Created successfully, Check Email OR SMS for password.');
            }
        } catch (\Exception $ex) {
            print_r($ex->getMessage());
            dd($ex->getLine());
           // $common     = new Common();
           // $common->error_logging($ex, 'register', 'RegisterController.php');
           // return view('layouts.coming_soon');
        }
    }


    public function loginUser(Request $request) {
        $this->validateLogin($request);

        // If the class is using the ThrottlesLogins trait, we can automatically throttle
        // the login attempts for this application. We'll key this by the username and
        // the IP address of the client making these requests into this application.
        if (
            method_exists($this, 'hasTooManyLoginAttempts') &&
            $this->hasTooManyLoginAttempts($request)
        ) {
            $this->fireLockoutEvent($request);
            return $this->sendLockoutResponse($request);
        }

        //Check OTP is valid for perticular user
        $requestData = $request->all();
        if (filter_var($requestData['email'], FILTER_VALIDATE_EMAIL)) {
            $usernameType = 'email';
        } else {
            $usernameType = 'mobile_no';
        }

        $otpOrPassword = isset($requestData['otp']) ? $requestData['otp']: $requestData['password'];

        return $requestData['password'];
        // Using Password login
        if(!empty($requestData['password'])){
            if(!empty( $requestData['company_id'])){
                $user = User::where('company_id', $requestData['company_id'])->where($usernameType, $requestData['email'])->first();
                if(Auth::loginUsingId($user->id))
                    return $this->sendLoginResponse($request);
            }else{
                if ($this->attemptLogin($request))
                    return $this->sendLoginResponse($request);
            }
        }

        // Using OTP Login
        $otpData = OtpModel::where('otp', '=', $otpOrPassword)
        ->where('status', '=', '0')
        ->where($usernameType, '=', $requestData['email'])
        ->where('created_at', '>=',  DB::raw('NOW() - INTERVAL 10 MINUTE')) // OTP available only for 10 minutes after registration.
        ->orderBy('id','desc')
        ->first();

        $userId = !empty($otpData->user_id) ? $otpData->user_id : null;

        if(!empty($requestData['company_id']) && !empty($otpData)){
            $userData1 = User::where('company_id', $requestData['company_id'])->where($usernameType, $requestData['email'])->first();
            $userId = $userData1->id;
        }

        if (!empty($userId) && Auth::loginUsingId($userId)) {
            $otpData = OtpModel::where('user_id', $userId)->where('status', 0)->where('otp', '=', $otpOrPassword)
            ->update(['status' => 1, 'updated_by' => $userId, 'updated_at' => Carbon::now()->toDateTimeString()]);
            return $this->sendLoginResponse($request);
        }


        $request['password'] = isset($request->password) ? $request->password: '';

        if ($this->attemptLogin($request)) {
            return $this->sendLoginResponse($request);
        }

        //Using OTP get user id and pass into loginUsingId
        // If the login attempt was unsuccessful we will increment the number of attempts
        // to login and redirect the user back to the login form. Of course, when this
        // user surpasses their maximum number of attempts they will get locked out.
        $this->incrementLoginAttempts($request);
        return $this->sendFailedLoginResponse($request);
    }

    protected function validateLogin(Request $request) {
        $requseData = $request->all();

        if (isset($requseData['otp'])) {
            $request->validate([
                $this->username() => 'required|string',
                'otp' => 'required|string',
            ]);
        } else {
            $request->validate([
                $this->username() => 'required|string',
                'password' => 'required|string',
            ]);
        }
    }


    /**
     * @param $request
     * @param $media
     * @return array
     * @description This method user for login and manage that user session.
     */
    public static function userAuthenticate(Request $request)
    {
        try {

            // $AUTH_EXP_101   = 'These credentials do not match in our records.';
            $AUTH_EXP_102   = 'More than one companies assign to the user.';
            $validation     = self::checkAuthValidation($request);
            if (!empty($validation)) {
                return $validation;
            }

            if (self::userCompaniesCount($request) > 1) {
                $user = self::checkUserDefaultCompany($request);
                if (!empty($user)) {
                    $request->company_id = $user->company_id;


                    return self::userAuthorization($request);
                }
                return [
                    'exception' => self::get_translation('AUTH_EXP_102', $AUTH_EXP_102),

                    'userCompanies' => self::userCompanies($request) //Return all companies associated to user.
                ];
            }

            return self::userAuthorization($request);


        } catch (\Exception $ex) {
            print_r($ex->getMessage);
            //(new Common())->error_logging($ex, 'userAuthenticate', 'UserController.php');
            //return view('errors.oh!');
        }
    }

    /**
     * @param $request - hold request data into request parameter.
     * @return array - this function returns collection of error.
     */
    public static function checkAuthValidation($request)
    {
        try {
            $AUTH_EXP_101 = 'These credentials do not match in our records.';
            $field  = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';

            if (!empty($request->password)) {
                $userList = User::where($field, $request->email)->get();
                if (!empty($userList)) {
                    foreach ($userList as $userDetails) {
                        if (Hash::check($request->password, $userDetails->password)) {
                            $userDetail = $userDetails;
                            break;
                        }
                    }
                }
                if (empty($userDetail)) {
                    return ['exception' => ['global' => self::get_translation('AUTH_EXP_101', $AUTH_EXP_101)]];
                }
            } else {
                return self::validateOTP($request);
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'checkAuthValidation', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    public static function validateUser($request)
    {
        try {
            $VALID_USR_EXP_101 = 'This Email/Mobile No. is not registered.';
            $field  = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';

            $user   = User::where($field, $request->email)->first();
            if (empty($user)) {
                return ['exception' => ['global' =>self::get_translation('VALID_USR_EXP_101', $VALID_USR_EXP_101)]];
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'validateUser', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param Request $request
     * @return mixed
     * @description This method return associated companies related to user
     */
    public static function userCompaniesCount(Request $request)
    {
        try {
            $field = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';
            return User::where($field, $request->email)->count();
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'userCompanies', 'UserController.php');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param $request
     * @return mixed
     * @description This method return associated companies related to user.
     */
    public static function userCompanies($request)
    {
        try {
            $field = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';

            return User::select('users.*', 'company.*', 'users.id AS user_id')
                ->leftJoin('company', 'users.company_id', 'company.id')
                ->where($field, $request->email)
                ->get();
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'userCompanies', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param Request $request
     * @return array|\Illuminate\Http\JsonResponse
     * @description This method user for authentication if user credentials is correct then this method store user detail into session.
     */
    public static function userAuthorization(Request $request)
    {

        try {

            $AUTH_SUC_LOG_IN    = 'You have successfully logged into the S2G.';
            $field              = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';
            $passType           = !empty($request->password) ? 'password' : 'otp';

            $user               = self::getUserBy($field, $request->email, !empty($request->company_id) ? $request->company_id : '');
            $token              = Auth::login($user);


             if (!empty($request->company_id) && !empty($request->make_default) && $request->make_default == 'on') {
                 self::setUserDefaultCompany($request);
             }

            //Store Login Report
            $media = $request->is('api/*') ? 'app' : 'web';
            self::storeLoginReport($user, $token, $field, $passType, $media);

            if ($request->is('api/*')) {
                return response()->json(['token' => $token]);
            } else {
                self::manageSession();
                return ['success' =>self::get_translation('AUTH_SUC_LOG_IN', $AUTH_SUC_LOG_IN)];
            }

        } catch (\Exception $ex) {
            print_r($ex->getMessage());
            dd($ex->getLine());
            //(new Common())->error_logging($ex, 'userAuthorization', 'UserController.php');
            // return view('errors.oh!');
        }
    }

    /**
     * @param Request $request
     * @return mixed
     * @description This method check default company related to user.
     */
    public static function checkUserDefaultCompany(Request $request)
    {
        try {
            $field = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';
            return User::where($field, $request->email)
                ->where('make_default', '1')
                ->first();
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'checkUserDefaultCompany', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param Request $request
     * @description This method use for set default company to related user.
     */
    public static function setUserDefaultCompany(Request $request)
    {
        try {
            $field = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';
            User::where($field, $request->email)->update(['make_default' => '0']);
            User::where($field, $request->email)->where('company_id', $request->company_id)->update(['make_default' => '1']);
        } catch (\Exception $ex) {
           // (new Common())->error_logging($ex, 'setUserDefaultCompany', 'UserController.php');
          //  return view('errors.oh!');
          print_r($ex->getMessage());
          dd($ex->getLine());
        }
    }

    /**
     *@description This function store custom session data into "user_info"
     */
    public static function manageSession()
    {
        try {
            $user                   = Auth::user();
          //  $success['token']       = $user->createToken('S2G')->accessToken;
            $companyID              = $user->company_id;
            $roleDetails            = self::getUserRoleDetail($user->id);

            $sessionData['user_id']     = $user->id;
            $sessionData['user_name']   = $user->name;
           // $sessionData['token']       = $success['token'];
            $sessionData['email']       = $user->email;
            $sessionData['company_id']  = $companyID;
            $sessionData['start_time']  = Carbon::now()->toDateTimeString();
            $sessionData['role_id']     = !empty($user->role_id) ? $user->role_id : '';
            $sessionData['redirect_url'] = !empty($roleDetails) ? $roleDetails->redirect_url : 'home';
            $sessionData['ip_address']  = request()->server('REMOTE_ADDR');
            Session::put('user_info', $sessionData);
            return;
        } catch (\Exception $ex) {
           // (new Common())->error_logging($ex, 'userAuthenticate', 'UserController.php');
            //return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    public static function sendOTP(Request $request)
    {
        try {
            $OTP_SND_SUC_01 = 'OTP send on your registered Email or Mobile no.';
            $OTP_USR_NOT_FND_01 = 'User detail not found.';

            $request->merge(['email' => $request->userID]);
            $validation = self::validateUser($request);
            if (!empty($validation)) {
                return $validation;
            }

            $field  = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';
            $user   = self::getUserBy($field, $request->email);
            $otp    = mt_rand(1000, 9999);

            if (!empty($user)) {
                $storeOtpDetails['user_id'] = $user->id;
                $storeOtpDetails['otp_send'] = $request->userID;
                $storeOtpDetails['email'] = $user->email;
                $storeOtpDetails['mobile_no'] = $user->mobile_no;
                $storeOtpDetails['otp'] = $otp;
                $storeOtpDetails['status'] = '0';

                //Send OTP email to user for login
                /*$email = new Email();
                $email->content_email(
                    $user->email,
                    $user->name,
                    'Email OTP Verification',
                    '',
                    'Hi ' . $user->mobile_no . '<br> Thank You for registering on Skill2Gether. Below is your one time password: <br>' . $otp . '<br><br><br> We are always available at your service. Feel free to connect at hello@skill2gether.in<br><br><br<br>Sincerely<br>Team Skill2Gether'
                );*/

                /*//Send OTP sms to user for login
                $sms = new SMS();
                $sms->send_sms(
                    $user->mobile_no,
                    'Your OTP for your S2G account is ' . $otp . '. Use this OTP for Login',
                    $user->id
                );*/

                $masterModel = new MasterModel();
                $masterModel->insertData($storeOtpDetails, 'login_with_otp');

                EmailMasterController::sendAlert('SEND_OTP', ['user_id' =>  $user->id]);
                //EmailMasterController::sendAlert('USER_REG', ['user_id' =>  $user->id]);
                return ['success' => ['otp' => self::get_translation('OTP_SND_SUC_01', $OTP_SND_SUC_01)]];
            }
            return ['exception' => self::get_translation('OTP_USR_NOT_FND_01', $OTP_USR_NOT_FND_01)];
        } catch (\Exception $ex) {
            print_r ($ex->getMessage());exit;
           // (new Common())->error_logging($ex, 'sendOTP', 'UserController.php');
           // return view('errors.oh!');
        }
    }

    public static function validateOTP($request)
    {
        try {
            $VAL_OTP_EXP_101 = 'Enter valid OTP OR generate new OTP and try again.';
            $VAL_OTP_EXP_102 = 'OTP entered is expired. Please generate new OTP and try again.';
            $requestData    = $request->all();
            $otpData        = OtpModel::where('status', '=', '0')
                ->where('otp_send', $requestData['email'])
                ->orderBy('created_at', 'DESC')
                ->first();

            if (empty($otpData)) {
                return ['exception' => ['otp' => self::get_translation('VAL_OTP_EXP_101', $VAL_OTP_EXP_101)]];
            }

            if (!empty($otpData) && $otpData->otp != $requestData['otp']) {
                return ['exception' => ['otp' => self::get_translation('VAL_OTP_EXP_101', $VAL_OTP_EXP_101)]];
            }

            $startDate  = new \DateTime($otpData->created_at);
            $difference = $startDate->diff(new \DateTime(date('Y-m-d H:i:s')));
            if (!empty($difference)) {
                if ($difference->d != 0 && $difference->i > 10) {
                    return ['exception' => ['otp' => self::get_translation('VAL_OTP_EXP_102', $VAL_OTP_EXP_102)]];
                }
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'validateOTP', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param $request
     * @return mixed
     * @description This method user for create new user with the input parameters and return result.
     */
    public static function createUser($request)
    {
        try {
            $regValidation = self::registrationValidation($request);
            if (!empty($regValidation)) {
                return $regValidation;
            }
            $referralID = self::generateReferralID(9);
            $companyID  = !empty($request->company_id) ? $request->company_id : 999;

            $firmName = '';
            if (!empty($request->company_id)) {
                 $companyDetail = DB::table('company')->where('id', '=', $companyID)->first();
                // Swapnil 16-May-21 -- SGWE-133 -- use the function from CommonBaseController
               // $companyDetail = CommonBaseController::getCompanyInfo($companyID);
                $firmName = !empty($companyDetail) ? $companyDetail->company_name : '';
            }

            $languageID = 4;
            $languageCode = 'EN';
            $languageDescription = 'English';
            if (!empty($request->language_code)) {
                $language = DB::table('general_master')
                            ->where('master_code', '=', 'LANG')
                            ->where('code', '=', $request->language_code)
                            ->first();
                if (!empty($language)) {
                    $languageID = $language->id;
                    $languageCode = $language->code;
                    $languageDescription = $language->description;
                }
            }

            $statusCode = 'ACT';
            $statusDescription = 'Active';
            if (!empty($request->status_code)) {
                $statusDetail = DB::table('general_master')->where('master_code', '=', 'STATUS')->where('code', '=', $request->status_code)->first();
                if (!empty($statusDetail)) {
                    $statusCode = $request->status_code;
                    $statusDescription = $statusDetail->description;
                }
            }

            // $roleDetail = RoleModel::where('company_id', $companyID)->where('role', 'Admin')->first();
            // Swapnil 16-May-21 -- SGWE-133 -- Shifted the query to CommonBaseController
            $roleDescription = 'Admin';
            $roleDetail = self::getCompanyRoles($companyID, $roleDescription);

            if(!empty($request->email) && !empty($request->mobile_no)) {
                $email = $request->email;
                $mobile = $request->mobile_no;
            } else {
                if(filter_var($request->email, FILTER_VALIDATE_EMAIL)){
                    $email = $request->email;
                    $mobile = '';
                } else {
                    $email = '';
                    $mobile = $request->email;
                }
            }

            //$email = !empty($request->email) ? $request->email : null;
            //$mobile = !empty($request->mobile_no) ? $request->mobile_no : null;
            $userdata = array(
                'name'                  => !empty($request->name) ? $request->name : '',
                'email'                 => $email,
                'mobile_no'             => $mobile,
                'firm_name'             => $firmName,
                'company_id'            => $companyID,
                'role_id'               => !empty($roleDetail) ? $roleDetail->id : null,
                'password'              => null,
                'language_id'           => $languageID,
                'language_code'         => $languageCode,
                'language_description'  => $languageDescription,
                'status_code'           => $statusCode,
                'status_description'    => $statusDescription,
                'is_deleted'            => 0,
                'profile_pic'           => 'images/dummy_profile.png',
                'referral_id'           => $referralID
            );

            if (isset($request->isCompleted)) {
                $userdata['is_completed'] = 1;
            } else {
                $userdata['is_completed'] = 0;
            }

            $user = User::create($userdata);
            self::sendNotification($user, $email, $mobile);
            // self::createGyanUser($request, '');
            // echo 'hiii';exit;
            return $user;
            //return $otp;

        } catch (\Exception $ex) {
            print_r($ex->getMessage());
            dd($ex->getLine());
           // (new Common())->error_logging($ex, 'createUser', 'UserController.php');
           // return view('errors.oh!');
        }
    }

    public static function registrationValidation(Request $request)
    {
        try {
            $USR_REG_INV_EMAIL_MOBILE = 'Please enter valid Email OR 10 digit Mobile No.';
            $field = filter_var($request->email, FILTER_VALIDATE_EMAIL) ? 'email' : 'mobile_no';
            if ($field == 'mobile_no' && (!is_numeric($request->email) || strlen($request->email) != 10)) {
                return ['exception' => ['email' => self::get_translation('USR_REG_INV_EMAIL_MOBILE', $USR_REG_INV_EMAIL_MOBILE)]];
            }
        } catch (\Exception $ex) {
           // (new Common())->error_logging($ex, 'registrationValidation', 'UserController.php');
            //return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param int $limit
     * @return string
     * @description This function generate user referral id and return to create user function.
     */
    public static function generateReferralID($limit = 9)
    {
        try {
            $code   = Str::random($limit);
            $cnt    = DB::table('users')
                ->where('referral_id', $code)
                ->count();
            if ($cnt > 0) {
                self::generateReferralID($limit);
            } else {
                return $code;
            }
        } catch (\Exception $ex) {
           // (new Common())->error_logging($ex, 'generateReferralID', 'UserController.php');
           // return view('errors.oh!');
           print_r($ex->getMessage());
           dd($ex->getLine());
        }
    }

    /**
     * @param $request
     * @return array
     * @description This function used for update user profile by user id
     */
    public static function updateUser(Request $request)
    {
        try {
            $USR_UPD_USER_INVALID_DETAIL = 'Please provide correct detail to update user profile.';
            if (!empty($request->user_id)) {
                $userDetail = self::getUserBy('id', $request->user_id);
                $UP_USR_EX01 = 'User not found.';
                $UP_USR_SU01 = 'User profile updated successfully.';

                if (!empty($userDetail)) {
                    //Mobile and Email if exist in DB then do not change existing.
                    if (!empty($userDetail->mobile_no)) {
                        $mobile = $userDetail->mobile_no;
                    } else {
                        $mobile = !empty($request->mobile_no) ? $request->mobile_no : $userDetail->mobile_no;
                    }
                    //Mobile and Email if exist in DB then do not change existing.
                    if (!empty($userDetail->email)) {
                        $email = $userDetail->email;
                    } else {
                        $email = !empty($request->email) ? $request->email : $userDetail->email;
                    }

                    $languageID = $userDetail->language_id;
                    $languageCode = $userDetail->language_code;
                    $languageDescription = $userDetail->language_description;
                    if (!empty($request->language_code)) {
                        $language = DB::table('general_master')
                            ->where('master_code', '=', 'LANG')
                            ->where('code', '=', $request->language_code)
                            ->first();
                        if (!empty($language)) {
                            $languageID = $language->id;
                            $languageCode = $language->code;
                            $languageDescription = $language->description;
                        }
                    } else if (!empty($request->language_id)) {
                        $language = DB::table('general_master')
                            ->where('master_code', '=', 'LANG')
                            ->where('id', '=', $request->language_id)
                            ->first();
                        if (!empty($language)) {
                            $languageID = $language->id;
                            $languageCode = $language->code;
                            $languageDescription = $language->description;
                        }
                    }

                    $statusCode = 'ACT';
                    $statusDescription = 'Active';
                    if (!empty($request->status_code)) {
                        $statusDetail = DB::table('general_master')->where('master_code', '=', 'STATUS')->where('code', '=', $request->status_code)->first();
                        if (!empty($statusDetail)) {
                            $statusCode = $request->status_code;
                            $statusDescription = $statusDetail->description;
                        }
                    }
                    $userdata = array(
                        'name'                  => !empty($request->name) ? $request->name : $userDetail->name,
                        'email'                 => $email,
                        'mobile_no'             => $mobile,
                        'firm_name'             => !empty($request->firm_name) ? $request->firm_name : $userDetail->firm_name,
                        'role_id'               => !empty($request->role_id) ? $request->role_id : $userDetail->role_id,
                        'language_id'           => $languageID,
                        'language_code'         => $languageCode,
                        'language_description'  => $languageDescription,
                        'updated_by'            => Auth::user()->id,
                        'status_code'           => $statusCode,
                        'status_description'    => $statusDescription
                    );
                    if (isset($request->isCompleted)) {
                        $userdata['is_completed'] = 1;
                    } else {
                        $userdata['is_completed'] = 0;
                    }
                    $user = User::where('id', $request->user_id)->update($userdata);
                    return ['success' => ['message' => self::get_translation('UP_USR_SU01', $UP_USR_SU01), 'user' => $userDetail]];
                }
                return ['exception' =>self::get_translation('UP_USR_EX01', $UP_USR_EX01)];
            }
            return ['exception' => self::get_translation('USR_UPD_USER_INVALID_DETAIL', $USR_UPD_USER_INVALID_DETAIL)];
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'updateUser', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param $request
     * @return array
     * @required-parameters [user_id, password, confirm_password]
     * @description This method use for update user password by user id.
     */
    public static function updateUserPassword(Request $request)
    {
        try {
            $USR_UPD_PASSWORD_SUC = 'Password updated successfully.';
            $USR_UPD_PASSWORD_ERR_MATCH = 'Password and Confirm password do not match.';
            $OTP_USR_NOT_FND_01 = 'User detail not found.';
            if (!empty($request->user_id)) {
                $userDetail = self::getUserBy('id', $request->user_id);
                if (!empty($userDetail)) {
                    /*if (!Hash::check($request->current_password, $userDetail->passowrd)) {
                        return ['exception' => 'Current password do not match in our records.'];
                    }*/
                    if ($request->password !== $request->confirm_password) {
                        return ['exception' => self::get_translation('USR_UPD_PASSWORD_ERR_MATCH', $USR_UPD_PASSWORD_ERR_MATCH)];
                    }
                    User::where('id', $request->user_id)->update([
                        'password' => bcrypt($request->password)
                    ]);
                    return ['success' =>self::get_translation('USR_UPD_PASSWORD_SUC', $USR_UPD_PASSWORD_SUC)];
                }
                return ['exception' => self::get_translation('USR_UPD_PASSWORD_SUC', $OTP_USR_NOT_FND_01)];
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'updateUserPassword', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param $request
     * @required-parameters [user_id & profile_pic]
     */
    /*
    public static function updateUserProfilePhoto(Request $request)
    {
        try {
            if (!empty($request->user_id)) {
                $user = self::getUserBy('id', $request->user_id);
                $request->merge(['param1' => 'company_id', 'value1' => $user->company_id]);
                $request->merge(['param2' => 'user_id', 'value2' => $user->id, 'folder_name' => '/profile_image']);
                $request->merge(['image_type_code' => 'USER_PROF_IMG', 'code_name' => 'USER_PROF_IMG', 'image_type_description' => 'User profile image']);

                UploadFilesController::upload_files($request);
                $imagePath = self::getLatestProfileImageFromFileUploadTable($user->id, $user->company_id);
                User::where('id', $request->user_id)->update(['profile_pic' => $imagePath]);
                return ['profile_pic' => $imagePath];
            }
        } catch (\Exception $ex) {
            (new Common())->error_logging($ex, 'updateUserProfilePhoto', 'UserController.php');
            return view('errors.oh!');
        }
    }
    **/
    /**
     * @param $request
     * @description This method use for make user active or inactive
     * @required-parameter [user_id & status]
     */
    public static function activeInactiveUser($request)
    {
        try {
            if (!empty($request->user_id) && !empty($request->status)) {
                $statusDesc = $request->status == 'ACT' ? 'Active' : 'Inactive';
                User::find($request->user_id)->update(['status' => $request->status, 'status_description' => $statusDesc]);
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'activeInactiveUser', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param $request
     * @return array
     * @description This method use for delete and retrieve user
     * @required-parameters [user_id & status]
     */
    public static function deleteRetrieveUser($request)
    {
        try {
            $USR_RET_USER_ERR = "You don't have permission to access this action.";
            $authDetail     = Auth::user();
            $authRoleDetail = self::getUserRoleDetail($authDetail->id);
            if (in_array($authRoleDetail->role, ['Super Admin', 'Collab Team'])) {
                User::where('id')->update(['is_deleted' => $request->status]);
            }
            return ['exception' => self::get_translation('USR_RET_USER_ERR', $USR_RET_USER_ERR)];
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'deleteRetrieveUser', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }


    public static function updateUserRole($request)
    {
        try {
        } catch (\Exception $ex) {

            return view('errors.oh!');
        }
    }

    public static function getUserBy($type, $value, $companyID = null)
    {
        try {
            $userDetail = User::select('users.*', 'roles.role', 'roles.redirect_url')
                ->leftJoin('roles', 'users.role_id', '=', 'roles.id')
                ->where('users.' . $type, '=', $value)
                ->where(function ($query) use ($companyID) {
                    if (!empty($companyID)) {
                        $query->where('users.company_id', $companyID);
                    } else {
                        $query->where('users.id', '!=', 0);
                    }
                })->first();
            return $userDetail;
        } catch (\Exception $ex) {
           // (new Common())->error_logging($ex, 'getUserBy', 'UserController.php');
          //  return view('errors.oh!');
          print_r($ex->getMessage());
          dd($ex->getLine());
        }
    }

    public static function getUserRoleDetail($userID, $companyID = null)
    {
        try {
            return DB::table('users')
                ->select('roles.*')
                ->leftJoin('roles', 'roles.id', '=', 'users.role_id')
                ->where('users.id', '=', $userID)
                ->where(function ($query) use ($companyID) {
                    if (!empty($companyID)) {
                        $query->where('roles.company_id', $companyID);
                    } else {
                        $query->where('roles.company_id', '!=', '-1');
                    }
                })
                ->first();
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'getUserRoleDetail', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    public static function storeLoginReport($user, $token, $userType, $passwordType, $media)
    {
       // dd($user);
        try {
            $currentDate    = Carbon::now();

            $masterModel                    = new MasterModel();
            $loggingReport['user_id']       = $user->id;
            $loggingReport['user_name']     = $user->name;
            $loggingReport['user_token']    = $token;
            $loggingReport['start_time']    = $currentDate->toDateTimeString();
            $loggingReport['media']         = $media;
            $loggingReport['username_type'] = $userType;
            $loggingReport['password_type'] = $passwordType;
            $loggingReport['session_type']  = '0';
            $loggingReport['created_by']    = $user->id;
            $loggingReport['updated_by']    = $user->id;

            if ($passwordType == 'otp') {
                OtpModel::where('user_id', '=', $user->id)->where('status', '=', '0')
                    ->update(array('status' => '1'));
            }
            $masterModel->insertData($loggingReport, 'login_report');
            return DB::table('roles')->where('id', '=', $user->role_id)->first();
        } catch (\Exception $ex) {
            //(new Common())->error_logging($ex, 'storeLoginReport', 'UserController.php');
            //return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param Request $request
     */
    // public function checkUserProfile(Request $request)
    // {
    //     try {
    //         $authDetail = Auth::user();

    //         if (Auth::check()) {
    //             if (empty($authDetail->name) || empty($authDetail->email) || empty($authDetail->mobile_no) || empty($authDetail->password)) {
    //                 $ddlLanguages = CommonBaseController::get_languages();
    //                 // $company = DB::table('company')->where('id', Auth::user()->company_id)->first();
    //                 $company = CommonBaseController::getCompanyInfo(Auth::user()->company_id);
    //                 $role = self::getUserRoleDetail(Auth::user()->id);
    //                 return ['exception' => ['view' => view('public-ui.themes.cake_theme.user-profile', compact('authDetail', 'ddlLanguages', 'company', 'role'))->toHtml()]];
    //             }
    //         }
    //         return ['success' => 'Do not show profile model.'];
    //     } catch (\Exception $ex) {
    //         (new Common())->error_logging($ex, 'checkUserProfile', 'UserController.php');
    //         return view('errors.oh!');
    //     }
    // }

    /**
     * @description This method use for redirect url for redirect after login
     */
    public static function getUserRedirectUrlAfterLogin()
    {
        try {
            $authDetail     = Auth::user();
            $roleDetails    = Self::getUserRoleDetail($authDetail->id, $authDetail->company_id);
            if (!empty(Session::get('url.intended'))) {
                $redirectTo = Session::get('url.intended');
            } else {
                $redirectTo = 'home';
                if (!empty($roleDetails) && in_array($roleDetails->redirect_url, ['super_admin', 'collab_admin', 'collab_team'])) {
                    $redirectTo = $roleDetails->redirect_url;
                }
            }
            return $redirectTo;
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'getUserRedirectUrlAfterLogin', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * @param $userDetail
     * @param $email
     * @param $mobile
     * @description This method use for sending OTP though the SMS and Email.
     */
    public static function sendNotification($userDetail, $email, $mobile)
    {
        try {
            // Send OTP & Welcome message to New User.
            $otp = mt_rand(1000, 9999);
            if (!empty($userDetail->id) && is_numeric($userDetail->id)) {
                $otpData = [
                    'user_id' => $userDetail->id,
                    'email' => $userDetail->email,
                    'mobile_no' => $userDetail->mobile_no,
                    'otp' => $otp,
                    'status' => 0
                ];
               // return $otpData;
                if (!empty($email)) {
                    $otpData['otp_send'] = $email;
                    OtpModel::create($otpData);
                }
                if (!empty($mobile)) {
                    $otpData['otp_send'] = $mobile;
                    OtpModel::create($otpData);
                }
                // try{
                //     EmailMasterController::sendAlert('NEW_PASSWORD', ['user_id' =>  $userDetail->id]);
                //     EmailMasterController::sendAlert('USER_REG', ['user_id' =>  $userDetail->id]);
                // }catch (\Exception $ex) {

                // }

            }
        } catch (\Exception $ex) {
           // (new Common)->error_logging($ex, 'sendNotification', 'RegisterController.php');
           // return view('errors.oh!');
           print_r($ex->getMessage());
           dd($ex->getLine());
        }
    }

   /* public static function getLatestProfileImageFromFileUploadTable($userID, $companyID)
    {
        try {
            $latestFile = UploadFilesModel::where('param1', 'company_id')
                ->where('value1', $companyID)
                ->where('param2', 'user_id')
                ->where('value2', $userID)
                ->where('code_name', 'USER_PROF_IMG')
                ->where('is_latest', '1')
                ->first();
            if (!empty($latestFile)) {
                return $latestFile->file_path;
            }
            return '';
        } catch (\Exception $ex) {
            (new Common)->error_logging($ex, 'sendNotification', 'RegisterController.php');
            return view('errors.oh!');
        }
    }
*/
    /**
     * @param $request
     * @param $password
     * @return \Illuminate\Contracts\View\Factory|\Illuminate\View\View
     * @description This method create gyan user.
     */
    static function createGyanUser($request, $password)
    {
        try {
            $data = [
                'name' => $request['name'],
                'phone' => $request['mobile_no'],
                'password' => $password,
                'email' => $request['email']
            ];

            $env_url = env('GYAN_URL', false);
            $url    = $env_url . '/services.php?function=userRegistration';
            $curl   = curl_init();

            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
            curl_setopt($curl, CURLOPT_URL, $url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

            $result = curl_exec($curl);
            curl_close($curl);
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'createGyanUser', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }







    /*This method need to be move to company controller*/
    public function index(Request $request)
    {
        try {
            // $requestData = $request->all();
            $sessionData    = $request->session()->get('user_info');
            $userDetail     = DB::table('users')->where('id', $sessionData['user_id'])->first();
            $task           = new MasterModel();
            $ddlLanguages   = $task->BindDDL($master_code = 'LANG');

            $data           = DB::table('users as  U')
                ->select('U.id', 'U.name', 'U.email', 'U.mobile_no', 'R.role', 'U.firm_name', 'C.company_name', 'U.language_id', 'U.profile_pic')
                ->leftJoin('roles as R', 'U.role_id', '=', 'R.id')
                ->leftJoin('company as C', 'U.company_id', '=', 'C.id')
                ->leftJoin('general_master as GM', 'U.language_id', '=', 'GM.id')
                ->where('U.id', '=', $sessionData['user_id'])
                ->where('GM.master_code', '=', 'LANG')
                ->first();
            //#dd($data);

            $activeCompanies = DB::table('users')
                ->select('users.*', 'company.company_name')
                ->join('company', 'company.id', '=', 'users.company_id')
                ->where('email', $userDetail->email)
                ->where('mobile_no', $userDetail->mobile_no)
                ->where('status_code', 'ACT')
                ->get();

            return view('layouts.user_profile', compact('ddlLanguages', 'data', 'userDetail', 'activeCompanies'));
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'index', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }
    // public function Update(Request $request, $id)
    // {
    //     try {
    //         // $user           = User::find($id);
    //         // $currentDate    = Carbon::now();
    //         // $sessionData    = $request->session()->get('user_info');
    //         // $requestData    = $request->all();
    //         // $updateData     = array();

    //         self::updateUser($request);
    //         self::updateUserPassword($request);

    //         if ($request->has('files')) {
    //             $request->merge(['user_id' => $id]);
    //             self::updateUserProfilePhoto($request);
    //         } else {
    //             // $filePath = null;
    //         }
    //         return redirect('/user_profile')->with('message', 'Profile updated successfully!');
    //     } catch (\Exception $ex) {
    //         (new Common())->error_logging($ex, 'Update', 'UserController.php');
    //         return view('errors.oh!');
    //     }
    // }

    /**
     * Store or Update Store Details
     * 1.   Create Store If not exist (when click on Seller Account) - Dashboard
     *      1.1     Create Company
     *      1.2     Create Store
     *      1.3     Create Role
     *      1.4     Create Master Data
     */
    static function StoreOrUpdateStoreDetails($requestData)
    {
        try {

            $companyId = self::StoreOrUpdateCompanyDetails($requestData);
            $masterModel = new MasterModel();

            $operationStoreDetails = [
                'company_id'        => $companyId,     //$requestData['list_id'],
                'store_name'        => $requestData['store_name'],
                'shop_start_date'   => $requestData['shop_start_date'],
                'store_url'         => $requestData['store_url'],
                'store_phone'       => $requestData['store_phone']
            ];

            if ($requestData['type'] == 'insert') {
                $storeId = $masterModel->insertData($operationStoreDetails, 'store_details');
                $storeSEODetails['store_id']    = $storeId;
                $storeSEODetails['is_deleted']  = '0';

                $masterModel->insertData($storeSEODetails, 'store_seo');
                $masterModel->insertData($storeSEODetails, 'store_more');
                return $storeId;
            } else if ($requestData['type'] == 'update') {
                $masterModel->updateData($operationStoreDetails, 'store_details', ['company_id' => $companyId]);
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'StoreOrUpdateStore', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    static function StoreOrUpdateCompanyDetails($requestData)
    {
        try {
            $masterModel = new MasterModel();
            $sessionData        = session('user_info');

            $companyDetails['company_name']     = !empty($requestData['store_name']) ? $requestData['store_name'] : 'No name';
            $companyDetails['is_deleted']       = '0';
            $companyId                          = $masterModel->insertData($companyDetails, 'company');

            //session(['user_info.company_id' => $companyId]);
            if (!in_array($sessionData['role_id'], ['4', '2'])) {
                //if ((!$sessionData['role_id'] == 4) || (!$sessionData['role_id'] == 2)) {
                session()->put('user_info.company_id', $companyId);
            }

            $extraData = [
                'user_id'    => $requestData['user_id'],
                'company_id' => $companyId
            ];

            // Assign New Company & Role to the User.
            self::assignRoleAndCompany($extraData);

            //Assign Company roles & their access.
            self::createMasterData($companyId);

            return $companyId;
        } catch (Exception $ex) {
            // (new Common())->error_logging($ex, 'sendNotification', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    static function createMasterData($companyId)
    {
        try {
            // Copy all roles from company id 10 to new company id.
            if (!empty($companyId)) {
                DB::select('call copy_dummy_data_from_company_10(?)', [$companyId]);
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'createMasterData', 'CompanyBaseController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    // Assign New role to the Company
    static function assignRoleAndCompany($extraData)
    {
        $sessionData        = session('user_info');
        $masterModel = new MasterModel();
        try {
            $extraSettings['where'] = [
                'where' => [
                    ['column' => 'company_id', 'expression' => '=', 'value' => $extraData['company_id']],
                    ['column' => 'role', 'expression' => '=', 'value' => 'Admin']
                ]
            ];

            $extraSettings['method'] = 'first';

            $roleDetails = self::getRoleDetails($extraSettings);
            $updateData = array();
            $where['id']                = $extraData['user_id'];
            $updateData['role_id']      = !empty($roleDetails->id) ? $roleDetails->id : '';
            $updateData['company_id']   = $extraData['company_id'];

            $masterModel->updateData($updateData, 'users', $where);
            if (!in_array($sessionData['role_id'], ['4', '2'])) {
                session()->put('user_info.role_id', $updateData['role_id']);
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'assignRole', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    // Get Role Details from company id;
    static function getRoleDetails($extraSettings)
    {
        try {
            $query  = DB::table('roles');
            $query  = MasterModel::queryBinder($extraSettings, $query);

            if (isset($extraSettings['method']) && $extraSettings['method'] == 'first') {
                $data = $query->first();
            } else {
                $data = $query->get();
            }
            return $data;
        } catch (Exception $ex) {
            // (new Common())->error_logging($ex, 'getRoleDetails', 'CompanyBaseController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    // Check here store url is already exist or not. If exist return false else true;
    static function check_duplicate_storeurl(Request $request)
    {
        try {
            $requestData = $request->all();
            if (isset($requestData['txturl']) && !empty($requestData['txturl'])) {
                $query1 = DB::table('store_details')
                    ->select('store_details.*')
                    ->where('store_details.store_url', $requestData['txturl'])
                    ->where('store_details.is_deleted', '=', '0')->first();
                if (!empty($query1)) {
                    return json_encode(false);
                } else {
                    return json_encode(true);
                }
            } else {
                return json_encode(false);
            }
        } catch (\Exception $ex) {
            // (new Common())->error_logging($ex, 'check_duplicate_storeurl', 'CompanyBaseController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }


    public function switchCompany(Request $request)
    {
        try {
            $requestData = $request->all();

            $user        = DB::table('users')
                ->where('email', $requestData['email'])
                ->where('mobile_no', $requestData['mobile_no'])
                ->where('company_id', $requestData['company_id'])
                ->first();

            Session::flush();

            $user = User::find($user->id);

            Auth::loginUsingId($user->id);

            if (!empty($request->make_default) && $request->make_default == 1) {
                DB::table('users')->where('email', $user->email)->update([
                    'make_default' => 0
                ]);
                DB::table('users')->where('id', $user->id)->update([
                    'make_default' => 1
                ]);
            }
            self::manageSession();
            /*$currentDate            = Carbon::now();
            $SEESION['user_id']     = $user->id;
            $SEESION['user_name']   = $user->name;
            $SEESION['token']       = $user->createToken('Collab')->accessToken;
            $SEESION['email']       = $user->email;
            $SEESION['company_id']  = $user->company_id;
            $SEESION['start_time']  = $currentDate->toDateTimeString();
            $SEESION['role_id']     = $user->role_id;
            $SEESION['redirect_url']= 'home';
            $SEESION['ip_address']  = 'web';//request()->server('REMOTE_ADDR');
            Session::put('user_info', $SEESION);*/
        } catch (\Illuminate\Database\QueryException $ex) {
            // (new Common())->error_logging($ex, 'switchCompany', 'UserController.php');
            // return view('errors.oh!');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    /**
     * Added by Shrikant on 31-Dec-20.
     */

    /**
     * Create New User (Registration)
     */
    /*static function createUser($data){
        try {
            $referralID     = Common::generateReferralID(9);
            $user = User::create([
                'name'                  => !empty($data['name']) ? $data['name'] : null,
                'email'                 => !empty($data['email']) ? $data['email'] : null,
                'mobile_no'             => !empty($data['mobile_no']) ? $data['mobile_no'] : null,
                'firm_name'             => !empty($data['firm_name']) ? $data['firm_name'] : null,
                'company_id'            => !empty($data['company_id']) ? $data['company_id'] : null,
                'role_id'               => !empty($data['role_id']) ? $data['role_id'] : null,
                'password'              => bcrypt($data['password']),
                'language_id'           => !empty($data['language_id']) ? $data['language_id'] : 4,
                'language_code'         => !empty($data['language_code']) ? $data['language_code'] : 'EN',
                'language_description'  => !empty($data['language_description']) ? $data['language_description'] : 'English',
                'status_code'           => !empty($data['status_code']) ? $data['status_code'] : 'ACT',
                'status_description'    => !empty($data['status_description']) ? $data['status_description'] : 'Active',
                'is_deleted'            => 0,
                'profile_pic'           => '',
                'referral_id'           => $referralID
            ]);
            return $user;
        }
        catch(Exception $ex){
            $common = new Common();
            $common->error_logging($ex, 'createUser', 'UserController.php');
            return view('layouts.coming_soon');
        }
    }*/

    /**
     * Send Notification after Register
     */
    /*static function sendNotification($userDetail, $password){
        try {
            if(!empty($userDetail->mobile_no) && is_numeric($userDetail->mobile_no)) {
                Common::send_sms( $userDetail->mobile_no, 'Dear, ' . $userDetail->name . ' Your new Account password is ' . $password);
            }

            if(!empty($userDetail)) {
                $email = new Email();
                $email->content_email($userDetail->email, $userDetail->user_name, 'Your Account password','', 'Dear, ' . $userDetail->name . '<br> Your new Account password is ' . $password);
            }
        }catch(Exception $ex){
            $common = new Common();
            $common->error_logging($ex, 'sendNotification', 'UserController.php');
            return view('layouts.coming_soon');
        }
    }*/



    /**
     * getCompanyRoles
     *
     * @param  mixed $companyID
     * @param  mixed $roleDescription
     * @return object
     * @vaibhav
     * @descriptiopn This function returns role details by passing role description and company id;
     */
    public static function getCompanyRoles($companyID, $roleDescription)
    {
        try {
            $roleDetail = RoleModel::where('company_id', $companyID)
            ->where('role', $roleDescription)
            ->first();
            return $roleDetail;
        } catch (\Exception $ex) {
           // $common     = new Common();
           // $common->error_logging($ex, 'getCompanyInfo', 'CommonBaseController.php');
           // return view('layouts.coming_soon');
           print_r($ex->getMessage());
           dd($ex->getLine());
        }
    }



    public static function get_translation($key, $description = null, $label = null, $length = null)
    {
        try {
            $locale = App::getLocale();
            // Commented By Swapnil on 01-12-2021
            // App::setLocale($locale);
            // if (Lang::has('app.' . $key)) {
            //     return trans('app.' . $key);
            // } else {
            //     return $description;
            // }
            $lang_str = "";
            App::setLocale($locale);
            if (Lang::has('app.' . $key)) {
                $lang_str = trans('app.' . $key);
                if (!empty($length)) {
                    $lang_str = self::get_short_string($lang_str, $length, $locale);
                }
                if (!empty($label) && Lang::has('app.' . $key . '_I')) {
                    $label = trans('app.' . $key . '_I');
                    if (strlen($label) > 10) {
                        $lang_str .= ' <i class="fa fa-info-circle" title="' . $label . '"></i>';
                    }
                }
            } else {
                if (!empty($description)) {
                    $lang_str = $description;
                } else {
                    App::setLocale('en');
                    if (Lang::has('app.' . $key)) {
                        $lang_str = trans('app.' . $key);
                        if (!empty($length)) {
                            $lang_str = self::get_short_string($lang_str, $length);
                        }
                        if (!empty($label) && Lang::has('app.' . $key . '_I')) {
                            $label = trans('app.' . $key . '_I');
                            if (strlen($label) > 10) {
                                $lang_str .= ' <i class="fa fa-info-circle" title="' . $label . '"></i>';
                            }
                        }
                    } else {
                        $lang_str = $key;
                        if (!empty($length)) {
                            $lang_str = self::get_short_string($lang_str, $length);
                        }
                    }
                }
            }
            return $lang_str;
        } catch (Exception $ex) {
          //  $common     = new Common();
           // $common->error_logging($ex, 'get_translation', 'Common.php');
           // return view('layouts.coming_soon');
           print_r($ex->getMessage());
           dd($ex->getLine());
        }
    }


    public static function get_short_string($val, $length, $locale = null)
    {
        try {
            $stringCut = mb_substr($val, 0, $length, 'utf8');
            $endpoint = mb_strrpos($stringCut, ' ', 0, 'utf8');
            //if the string doesn't contain any space then it will cut without word basis.
            $string = $endpoint && $endpoint > $length ? mb_substr($stringCut, 0, $endpoint, 'utf8') : mb_substr($stringCut, 0);
            //$string .= ' ...';
            return $string;
        } catch (Exception $ex) {
            // $common     = new Common();
            // $common->error_logging($ex, 'get_short_string', 'Common.php');
            // return view('layouts.coming_soon');
            print_r($ex->getMessage());
            dd($ex->getLine());
        }
    }

    public function logout(Request $request)
    {
        try {
            $requestData = $request->session()->all();
            $currentTime    = Carbon::now();

            if (isset($requestData['user_info']['token']) && !empty($requestData['user_info']['token'])) {
                LoggingReport::where('user_token', '=', $requestData['user_info']['token'])
                ->update(
                    array(
                        'end_time' => $currentTime,
                        'session_type' => '1'
                    )
                );
            }

            Auth::logout();

           //  $this->guard()->logout();
            Session::flush();
            $request->session()->invalidate();

            return redirect('/');
            //return $this->loggedOut($request) ? print_r('No redirexctedad'): redirect('/');
        } catch (Exception $ex) {
            //$common     = new Common();
            //$common->error_logging($ex, 'logout', 'LoginController.php');
            dd($ex->getMessage());
        }
    }
}
