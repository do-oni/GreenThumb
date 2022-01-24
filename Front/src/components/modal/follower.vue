<template>
  <div class="modal-mask">
    <div class="modal-wrapper">
      <div class="modal-container">
        <div class="modal-header">
          <slot name="follower"> default header </slot>
        </div>

        <div class="modal-body">
          <slot name="body">
            <div v-for="(followee, i) in followees" :key="i">
              <div class="input-group mb-3">
                <input
                  type="text"
                  class="form-control"
                  v-model.trim="followee.followeeNickName"
                  aria-label="Recipient's username"
                  aria-describedby="button-addon2"
                  readonly
                />
                <div>
                   <router-link  :to="{ name: 'plant', params: { userId: followee.followeeId} }">
                  <button
                    class="btn btn-primary"
                    type="button"
                    id="button-addon2"
                  >
                    식물보기
                  </button>
                  </router-link>
                
                </div>
              </div>
            </div>
          </slot>
        </div>
        <div class="modal-footer">
          <button class="modal-default-button" @click="$emit('close')">
            X
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
    
  
<script>
import { mapState } from "vuex";
import http from "@/util/http-common";

export default {
  data() {
    return {
      followees: [],
    };
  },
  computed: {
    ...mapState(["userInfo"]),
  },
  props: {
    feedowner: {},
  },
  created() {
    let token = localStorage.getItem("getToken");
    http
      .get("/follow-user/" + this.feedowner + "/followees", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        this.followees = res.data;
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {
      });
  },
};
</script>
  
  <style>
.modal-mask {
  position: fixed;
  z-index: 9998;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
  display: table;
  transition: opacity 0.3s ease;
}

.modal-wrapper {
  display: table-cell;
  vertical-align: middle;
}

.modal-container {
  width: 500px;
  height: 600px;
  margin: 0px auto;
  padding: 20px 30px;
  background-color: #fff;
  border-radius: 2px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.33);
  transition: all 0.3s ease;
  font-family: Helvetica, Arial, sans-serif;
}

.modal-header h3 {
  margin-top: 0;
  color: #42b983;
}

.modal-body {
  margin: 20px 0;
}

.modal-default-button {
  float: right;
}

.modal-enter {
  opacity: 0;
}

.modal-leave-active {
  opacity: 0;
}

.modal-enter .modal-container,
.modal-leave-active .modal-container {
  -webkit-transform: scale(1.1);
  transform: scale(1.1);
}
</style>
