<template>
  <div>
    <div
      class="btn-group"
      role="group"
      aria-label="Basic radio toggle button group"
    >
      <input
        type="radio"
        class="btn-check"
        name="btnradio"
        id="btnradio1"
        autocomplete="off"
        checked=""
        @click="editClick"
      />
      <label class="btn btn-outline-primary" for="btnradio1">정보 수정</label>

      <input
        type="radio"
        class="btn-check"
        name="btnradio"
        id="btnradio2"
        autocomplete="off"
        checked=""
        @click="postClick"
      />
      <label class="btn btn-outline-primary" for="btnradio2">내가 쓴 글</label>
      <input
        type="radio"
        class="btn-check"
        name="btnradio"
        id="btnradio3"
        autocomplete="off"
        checked=""
        @click="commentClick"
      />
      <label class="btn btn-outline-primary" for="btnradio3">내가 쓴 댓글</label
      >
    </div>
    <br /><br /><br />

    

    <div v-if="editFlag">
      <myprofile />
    </div>
    <div v-if="postFlag">
      <mypost />
    </div>
    <div v-if="commentFlag">
      <mycomment />
    </div>
  </div>
</template>

<script>
import myprofile from "../../components/mypage/Myprofiles.vue";
import mypost from "../../components/mypage/Myposts.vue";
import mycomment from "../../components/mypage/Mycomments.vue";

export default {
  components: {
    myprofile,
    mypost,
    mycomment,
  },
  data() {
    return {
      editFlag: true,
      postFlag: false,
      commentFlag: false,
    };
  },
  methods: {
    editClick() {
      this.editFlag = true;
      this.postFlag = false;
      this.commentFlag = false;
    },
    postClick() {
      this.editFlag = false;
      this.postFlag = true;
      this.commentFlag = false;
    },
    commentClick() {
      this.editFlag = false;
      this.postFlag = false;
      this.commentFlag = true;
    },

    created() {
      this.postFlag = false;
      this.commentFlag = false;
    },
  },
};
</script>

<style>
</style>