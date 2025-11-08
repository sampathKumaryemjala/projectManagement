export const UserRolesEnum = {
  ADMIN: "admin",
  PROJECT_ADMIN: "project_admin",
  MEMBER: "member",
};

// Available user roles as an array
export const AvailableUserRoles = Object.values(UserRolesEnum);

export const TaskStatusEnum = {
  TODO: "todo",
  IN_PROGRESS: "in_progress",
  DONE: "done",
};

export const AvailableTaskStatues = Object.values(TaskStatusEnum);



// Project member roles
export const ProjectRolesEnum = {
  OWNER: "owner",
  ADMIN: "admin",
  MEMBER: "member",
  VIEWER: "viewer",
};

// Available project roles as an array
export const AvailableProjectRoles = Object.values(ProjectRolesEnum);

// Project status
export const ProjectStatusEnum = {
  ACTIVE: "active",
  ON_HOLD: "on_hold",
  COMPLETED: "completed",
  ARCHIVED: "archived",
};

// Task priority
export const TaskPriorityEnum = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  URGENT: "urgent",
};
