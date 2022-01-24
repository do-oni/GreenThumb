<template>
  <div>
    <fieldset>
      <legend>
        <img src="../../assets/images/logo.png" width="500" height="100" />
      </legend>
      <div class="form-group row">
        <br />
      </div>
      <div class="form-group">
        <label
          for="exampleSelect1"
          class="form-label mt-4"
          style="float: left;">
          이메일
        </label>
        <input
          type="email"
          class="form-control"
          id="exampleInputEmail1"
          v-model="email"
          :rules="emailRules"
        />
        <br />
      </div>
      <div class="form-group">
        <label
          for="exampleSelect1"
          class="form-label mt-4"
          style="float: left;"
        >
          비밀번호
        </label>
        <input
          type="password"
          class="form-control"
          id="exampleInputPassword1"
          v-model="password"
          :counter="10"
        />
        <br />
        <br />
      </div>
    </fieldset>
    <button class="btn btn-primary" @click="login({ email, password })">
      로그인
    </button>
    <br />
    <br />
    <section>
      <OAuth2Login />
    </section>
  </div>
</template>

<script>
import OAuth2Login from '../../components/account/OAuth2Login.vue'
import { mapState, mapActions } from 'vuex'
export default {
  components: {
    OAuth2Login,
  },
  data: () => ({
    valid: true,
    // allUser: [],
    password: '',
    email: '',
    emailRules: [
      (v) => !!v || 'E-mail is required',
      (v) => /.+@.+\..+/.test(v) || 'E-mail must be valid',
    ],
  }),
  computed: {
    ...mapState(['isLogin', 'isLonginError']),
    // ...mapState({allUser: state => state.allUser})
  },
  methods: {
    ...mapActions(['login']),
  },
  beforeCreate() {
    this.$store.getters.loginCheck
  },
  validate() {
    this.$refs.form.validate()
  },
  reset() {
    this.$refs.form.reset()
  },
  resetValidation() {
    this.$refs.form.resetValidation()
  },
}
</script>
