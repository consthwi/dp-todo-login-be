const Task = require("../model/Task");

const taskController = {};

// Create Task
taskController.createTask = async (req, res) => {
  try {
    const { task, isComplete } = req.body;
    // 프론트엔드 요청에서 task, isComplete 수집
    const newTask = new Task({ task, isComplete });
    // Task모델 기반 newTask 생성
    await newTask.save();
    // 데이터베이스 newTask 저장
    res.status(200).json({ status: "ok", data: newTask });
  } catch (error) {
    res.status(400).json({ status: "fail", message: error.message });
  }
};

// Get Task
taskController.getTask = async (req, res) => {
  const taskList = await Task.find({});
  // 조건 없이 모든 데이터 query
  res.status(200).json({ status: "ok", data: taskList });
};

// Update Task1
// taskController.updateTask = async (req, res) => {
//   try {
//     const targetTask = await Task.findById(req.params.id);
//     // res.status(200).send(task);
//     // postman id-task 확인완료
//     // res.status(200).send(Object.keys(req.body));
//     // db에서 id로 선택한 데이터의 필드 값 전부 교체
//     const field = Object.keys(req.body);
//     field.map((value) => {
//       return (targetTask[value] = req.body[value]);
//     });
//     const updateTask = targetTask;
//     await updateTask.save();
//     res.status(200).json({ status: "ok", data: updateTask });
//     // db id해당데이터[task] = 요청한데이터[task]
//     // db id해당데이터[isComplete] = 요청한데이터[isComplete]
//   } catch (err) {
//     res.status(400).json({ status: "fail", error: err });
//   }
//   // targetTask업데이트 확인 완료
// };

// Update Task
taskController.updateTask = async (req, res) => {
  try {
    const updateTask = await Task.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true } // `new: true` return 새 문서
    );
    res.status(200).json({ status: "ok", data: updateTask });
  } catch (error) {
    res.status(400).json({ status: "fail", message: error.message });
  }
};

// Delete Task
taskController.deleteTask = async (req, res) => {
  try {
    const targetTask = await Task.findByIdAndDelete(req.params.id);
    res.status(200).json({ status: "ok", data: targetTask });
  } catch (error) {
    res.status(400).json({ status: "fail", message: error.message });
  }
  // targetTask제거 확인 완료
};

module.exports = taskController;
