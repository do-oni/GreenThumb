<template>
  <div>
    <v-form v-model="form">
      <fieldset>
        <legend>
          <img src="../../assets/images/logo.png" width="500" height="100">
        </legend>
        <div class="form-group row">
          <br>
        <v-img src="https://i.ibb.co/1ZYtvQ8/logo.png" height="100px" width="500px"/>
          <br>
        </div>
        <div class="form-group">
          <label for="exampleSelect1" class="form-label mt-4" style="float:left;">
            이메일
          </label>
          <input
            type="email"
            class="form-control"
            id="exampleInputEmail1"
            v-model="email"
            :rules="[rules.email]"
          />
          <br>
        </div>
        <div class="form-group">
        <label for="exampleSelect1" class="form-label mt-4" style="float:left;">
            비밀번호
          </label>
          <input
            type="password"
            class="form-control"
            id="exampleInputPassword1"
            v-model="password"
            :rules="[rules.password, rules.length(6)]"
          />
          <br>
        </div>
        <div class="form-group">
          <label for="exampleSelect1" class="form-label mt-4" style="float:left;">닉네임</label>
          <input type="text" class="form-control" id="inputDefault">
        </div>
        </fieldset>
        <br>
        <div class="form-group">
      <label for="exampleSelect1" class="form-label mt-4" style="float:left;">프로필 사진</label>
      <input class="form-control" type="file" id="formFile">
    </div>
        <br><br>
        <fieldset>
        <button type="submit" class="btn btn-primary" 
        @click="submitForm">회원가입</button>
      </fieldset>
      <br><br>
      <section>
      <OAuth2Signup/>
      </section>
    </v-form>
  </div>
</template>

<script>
import OAuth2Signup from '../../components/account/OAuth2Signup.vue';
import http from "@/util/http-common";

export default {
  components : {
    OAuth2Signup
  },
  name: "signup",

  data () {
    return {
    agreement: false,
    nickName: '',
    dialog: false,
    email: '',
    form: false,
    isLoading: false,
    password: '',
    password2: '',
    rules: {
      email: v => !!(v || '').match(/@/) || 'Please enter a valid email',
      length: len => v => (v || '').length >= len || `Invalid character length, required ${len}`,
      password: v => !!(v || '').match(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*(_|[^\w])).+$/) ||
        'Password must contain an upper case letter, a numeric character, and a special character',
      password2: v => v === this.password || "패스워드가 일치하지 않습니다.",
      required: v => !!v || 'This field is required',
    }
  }
},
methods: {
       submitForm() {
      http
        .post("/auth/signup", {
          email: this.email,
          password: this.password,
          nickName: this.nickName,
        })
        .then((response) => {
          if(response.data.success == true){
            alert("회원가입 성공")
            this.$router.push({ name: 'login'})
          }else{
            alert("회원가입 실패")
          }
        })
        .catch((error) => {
          console.log(error);
        });
      }
    }
  }
</script>