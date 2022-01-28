
 @extends('public-ui.includes.public-layout')

@section('extra-js')
    <script src="{{ asset('vendor/auth/js/auth.js') }}"></script>
@endsection
@section('page-content')
    <section id="register">
        <div class="container">
            @if(Session::has('success'))
                <div class="alert alert-success">
                    {{Session::get('success')}}
                </div>
            @endif
            <div class="row">
                <div class="col-md-8 text-center border-right my-5">
                    <h6 class="text-center font_weight500 text_black font_18px">Everything about Construction Machines</h6>
                    <p class="text-center t_paragraph font_13px text-dark">Get or give construction Machines on rent,<br>
                        used sale,new sale or job work
                    </p>
                    <div class="w-100">
                        <img class="text-center" width="60%" src="{{asset('/public-ui/images/register.png')}}">
                    </div>
                </div>
                <div class="col-md-4 text-center pl-4 my-5">
                    <img src="<?php echo asset('/').'public-ui/images/';  ?>SM_logo-(2).png" width="150px">
                    @if($errors->has('global'))
                        <div class="alert alert-danger m-0 mt-2 p-1 rounded-0">
                            <div class="error">{{ $errors->first('global') }}</div>
                        </div>
                    @endif
                    @if($errors->has('many_companies'))
                        <div class="alert alert-danger m-0 mt-2 p-1 rounded-0">
                            <div class="error">You are associated on more than one companies, please select company</div>
                        </div>
                    @endif
                    <form method="POST" action="@if($errors->has('many_companies')) {{url('/user-authorization')}} @else {{url('/user-authenticate')}} @endif" autocomplete="off" class="mt-3" id="login-form">
                        {{--<input type="hidden" name="company_id" id="company-id" value="">
                        <input type="hidden" name="make_default" id="make-default" value="0">--}}
                        @csrf
                        <div class="form-group">
                            <input type="hidden" name="media" value="web">
                            <input id="email" type="text" class="form-control @error('email') is-invalid @enderror" name="email" value="{{old('email')}}" required autocomplete="email" autofocus placeholder="Enter Email / Mobile no">
                            @error('email')
                            <span class="invalid-feedback" role="alert" style="display: block !important;">
                                <strong>{{ $message }}</strong>
                            </span>
                            @enderror
                        </div>
                        <div class="form-group text-left">
                            <input id="password" type="password" value="@if($errors->has('many_companies')) {{old('password')}} @endif" class="form-control @error('password') is-invalid @enderror" name="{{!empty($_GET['otp']) && $_GET['otp'] == 'true' ? 'otp' : 'password'}}" required autocomplete="current-password" placeholder="{{!empty($_GET['otp']) && $_GET['otp'] == 'true' ? 'Enter OTP' : 'Enter Password'}}">
                            @error('password')
                            <span class="invalid-feedback" role="alert" style="display: block !important;">
                                <strong>{{ $message }}</strong>
                            </span>
                            @enderror
                            @if($errors->has('otp'))
                                <span class="invalid-feedback" role="alert" style="display: block !important;">
                                <strong>{{ $errors->first('otp') }}</strong>
                            </span>
                            @endif
                        </div>

                        @if($errors->has('many_companies'))
                            <div class="form-group text-left">
                                <select class="form-control" name="company_id" required>
                                    <option value="">Select</option>
                                    @foreach(json_decode($errors->first('many_companies')) as $company)
                                        <option value="{{$company->company_id}}">{{$company->company_name}}</option>
                                    @endforeach
                                </select>

                                <div>
                                    <input type="checkbox" name="make_default"> If you want to make default above company.
                                </div>
                            </div>
                        @endif

                        <button type="submit" class="btn btn-sky-blue mt-1 px-5 font_size14" id="login_btn">
                            {{ __('Login') }}
                        </button>
                        {{--@if (Route::has('password.request'))
                            <a class="btn btn-link" href="{{ route('password.request') }}">
                                {{ __('Forgot Your Password?') }}
                            </a>
                        @endif--}}
                        <input type="button" id="login_with_otp" class="btn btn-outline-sky-blue mt-1 ml-3 font_size14" value="{{!empty($_GET['otp']) && $_GET['otp'] ? 'Login with password' : 'Login with OTP'}}">
                        {{-- <input type="button" class="btn btn-primary" id="send-otp" value="Login with OTP">--}}
                    </form>
                    <div class=" mt-2">
                        <p class="font_14px text_black">Don't have an account? <a href="<?php echo URL::to('/register');?>" class="t_color">Sign up</a></p>
                    </div>

                    {{-- <div class="border_left_right">
                        <p class="t_color">Or login with</p>
                    </div>
                    <div class="social mt-2">
                        <a href="#"  class="nounderline"><img class="px-4 border-right" src="{{asset('/').'public-ui/images/facebook.png'}}"> </a>
                        <a href="#"  class="nounderline"><img class="px-4 border-right" src="{{asset('/').'public-ui/images/linkdin.png'}}"> </a>
                        <a href="#"  class="nounderline"><img class="px-4" src="{{asset('/').'public-ui/images/google_plus.png'}}"></a>
                    </div> --}}
                </div>
            </div>
        </div>
    </section>

    <!-- Modal -->
    <div class="modal fade" id="login_with_otp_Modal" role="dialog">
        <div class="modal-dialog">
            <!-- Modal content-->
            <div class="modal-content">
                <div class="modal-header">
                    <div class="loading"></div>
                    <h5 class="font_weight500 font_20px text_black">Lost your password? </h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close" style="margin-top: -20px;">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div id="sendOTP">
                    <div class="modal-body">
                        <span class="font_13px text_black">Please enter your email address or mobile no. You will receive a OTP via email / mobile no.</span>
                        <input id="uer_id" type="text" class="form-control @error('email') is-invalid @enderror" name="email" value="" required autocomplete="email" autofocus>
                        <span id="error_msg" style="color: red; font-size: 13px;"></span>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default btn-outline-sky-blue font_14px text_black" data-dismiss="modal">Close</button>
                        <input type="button" class="btn btn-sky-blue font_14px" name="sendOTP" value="Send OTP" id="send-otp">
                    </div>
                </div>
                <div id="verifyOTP" style="display: none;">
                    <div class="modal-body">
                        <span id="success_msg" style="color: red; font-size: 13px;"></span>
                        <input type="text" placeholder="Enter Otp" name="verify-otp" class="form-control" id="OTP">
                        <span id="msg" style="color: red; font-size: 13px;"></span>
                        <div id="alert" style="color: red; text-align: center;"></div>
                    </div>
                    <div class="modal-footer">
                        <input type="button" class="btn btn-primary" name="verifyOTP" value="verify OTP" id="verify-otp">
                    </div>
                </div>
                <div id="changePassword" style="display: none;">
                    <div class="modal-body">
                        <span id="success_msg" style="color: red; font-size: 13px;"></span>
                        <input type="password" placeholder="Enter Password" name="password" class="form-control" id="new_password">
                        <input type="password" placeholder="Enter Confirm Password" name="conf_password" class="form-control" id="conf_password">
                        <span id="password_msg" style="color: red; font-size: 13px;"></span>
                    </div>
                    <div class="modal-footer">
                        <input type="button" class="btn btn-primary" name="change_password" value="Update" id="change_password">
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Use for Current access of company Yes / No -->
    <div class="modal fade" id="company-dropdown-modal" tabindex="-1" role="dialog" aria-labelledby="company-dropdown-label" aria-hidden="true">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="company-dropdown-label" style="float: left;">Select a Company</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="row">
                        <div class="col-md-12 text-center">
                            <p>Please select a Company to proceed.</p>
                        </div>
                        <div class="col-md-2"></div>
                        <div class="col-md-8">
                            <div class="form-group">
                                <input type="hidden" name="media" value="web">
                                <select id="companies" class="form-control form-control-sm"></select>
                                <span class="invalid-feedback" role="alert" style="display: block">
                                <strong id="select-company-msg"></strong>
                            </span>
                            </div>
                            <label class="font-weight-normal">
                                <input type="checkbox" name="make_primary" id="user-make-default" value="1" style="position: relative; top: 1.5px;"> Make primary
                            </label>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-sky-blue float-right company-chosen-submit">Submit</button>
                </div>
            </div>
        </div>
    </div>
@stop
