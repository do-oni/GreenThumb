<template>
  <div>
    <div class="form-group">
      <fieldset>
        <input
          class="form-control"
          id="readOnlyInput"
          type="text"
          placeholder="이메일"
          readonly=""
          :value="email"
        />
      </fieldset>
    </div>
    <br /><br />

    <div class="form-group">
      <div class="input-group mb-3">
        <input
          type="text"
          class="form-control"
          placeholder="닉네임"
          aria-label="Recipient's username"
          aria-describedby="button-addon2"
          v-model="nickName"
        />
        <!-- <button class="btn btn-primary" type="submit" id="button-addon2">
          변경
        </button> -->
      </div>
    </div>
    <br />

    <div class="form-group">
      <textarea class="form-control" v-model="profile" placeholder="프로필" rows="3"></textarea>
    </div>

    <br />

    <div class="form-group">
      <fieldset>
        <input
          class="form-control"
          id="readOnlyInput"
          type="text"
          placeholder="가입일자"
          readonly=""
          :value="signUpDate"
        />
      </fieldset>
    </div>
    <br /><br />

    <div class="form-group">
      <fieldset>
        <input
          class="form-control"
          id="readOnlyInput"
          type="text"
          placeholder="가입경로"
          readonly=""
          :value="provider"
        />
      </fieldset>
    </div>

    <!-- <div class="form-group">
      <label for="formFile" class="form-label mt-4">프로필 사진</label>
      <input class="form-control" type="file" id="formFile" />
    </div> -->
    <br/>
        <div>
          <button type="button" class="btn btn-primary" @click="validate">수정</button>
        </div>
  </div>
</template>
<script>
import http from "@/util/http-common";
export default {
  data: () => ({
    valid: true,
    User: [],
    email: "",
    nickName: "",
    signUpDate: "",
    profile: "",
    provider: "",
    checkbox: false,
  }),
  props: {
    userId: {},
  },

  created() {
    let userId = localStorage.getItem("getId");
    let token = localStorage.getItem("getToken");
    http
      .get("/user/" + userId, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        (this.email = res.data.email),
          (this.nickName = res.data.nickName),
          (this.profile = res.data.profile),
          (this.provider = res.data.provider),
          (this.signUpDate = res.data.signUpDate);
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {});
  },

  methods: {
    validate() {
      // this.$refs.form.validate();
      let token = localStorage.getItem("getToken");
      let userId = localStorage.getItem("getId");
      var data = {
        nickName: this.nickName,
        profile: this.profile,
      };
      console.log(this.nickName);
      console.log(this.profile);
      http
        .put("user/" + userId, data, {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((res) => {
          console.log(res.data);
           alert("수정완료!");
          // this.$router.go(this.$router.currentRoute)
          this.$router.push({path: '/'});
        })
        .catch((err) => {
          console.log(err);
        })
    },
    reset() {
      this.$refs.form.reset();
    },
    // resetValidation() {
    //   this.$refs.form.resetValidation();
    // },
  },
};
</script>
<style></style>
