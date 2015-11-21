(ns new-admin.config
  (:require [taoensso.timbre :as timbre]))

(def defaults
  {:init
   (fn []
     (timbre/info "\n-=[new-admin started successfully]=-"))
   :middleware identity})
